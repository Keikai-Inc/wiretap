#!/usr/bin/env bash
#
# One-time AWS infrastructure setup for tap (`tap.keik.ai`).
#
# Mirrors hop's scripts/setup-aws.sh: creates an S3 bucket for
# release artifacts and the website, an Origin Access Control,
# a CloudFront distribution, and a bucket policy granting the
# distribution read access.
#
# This script is idempotent in the loose sense: re-running it
# *creates additional* resources rather than detecting existing
# ones (CloudFront has no native "create or update" idempotency
# anyway). The expected workflow is "run once, save the IDs."
#
# Cert + DNS attachment is documented at the bottom — those are
# semi-manual because they require waiting for ACM validation.
#
# Required env / defaults:
#   BUCKET                hop-tap-releases  (matches release.sh's default)
#   REGION                us-east-1         (CloudFront cert constraint)

set -euo pipefail

BUCKET="${HOP_TAP_RELEASE_BUCKET:-hop-tap-releases}"
REGION="${AWS_REGION:-us-east-1}"

echo "==> Creating S3 bucket: ${BUCKET} in ${REGION}"
if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  echo "    (bucket already exists, skipping create)"
else
  if [[ "${REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}"
  else
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}" \
      --create-bucket-configuration "LocationConstraint=${REGION}"
  fi
fi

echo "==> Blocking public access on bucket (CloudFront-only via OAC)"
aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "==> Creating CloudFront Origin Access Control"
OAC_ID=$(aws cloudfront create-origin-access-control \
  --origin-access-control-config \
    "Name=tap-releases-oac,Description=OAC for ${BUCKET},SigningProtocol=sigv4,SigningBehavior=always,OriginAccessControlOriginType=s3" \
  --query 'OriginAccessControl.Id' --output text)
echo "    OAC ID: ${OAC_ID}"

echo "==> Creating CloudFront distribution"
CALLER_REF="tap-releases-$(date +%s)"
DIST_CONFIG=$(cat <<EOF
{
  "CallerReference": "${CALLER_REF}",
  "Comment": "tap.keik.ai - tap releases + website",
  "Enabled": true,
  "DefaultRootObject": "index.html",
  "DefaultCacheBehavior": {
    "TargetOriginId": "tap-s3",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 2,
      "Items": ["GET","HEAD"],
      "CachedMethods": { "Quantity": 2, "Items": ["GET","HEAD"] }
    },
    "ForwardedValues": { "QueryString": false, "Cookies": { "Forward": "none" } },
    "MinTTL": 0,
    "DefaultTTL": 86400,
    "MaxTTL": 31536000,
    "Compress": true
  },
  "Origins": {
    "Quantity": 1,
    "Items": [
      {
        "Id": "tap-s3",
        "DomainName": "${BUCKET}.s3.${REGION}.amazonaws.com",
        "OriginAccessControlId": "${OAC_ID}",
        "S3OriginConfig": { "OriginAccessIdentity": "" }
      }
    ]
  },
  "PriceClass": "PriceClass_100"
}
EOF
)

DIST_OUTPUT=$(aws cloudfront create-distribution \
  --distribution-config "${DIST_CONFIG}" \
  --query 'Distribution.{Id:Id,Domain:DomainName}' --output json)

DIST_ID=$(echo "${DIST_OUTPUT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")
DIST_DOMAIN=$(echo "${DIST_OUTPUT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Domain'])")

echo "    Distribution ID:     ${DIST_ID}"
echo "    Distribution domain: ${DIST_DOMAIN}"

echo "==> Applying bucket policy (grant CloudFront read access)"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontServicePrincipalReadOnly",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET}/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::${ACCOUNT_ID}:distribution/${DIST_ID}"
        }
      }
    }
  ]
}
EOF
)
aws s3api put-bucket-policy --bucket "${BUCKET}" --policy "${POLICY}"

echo ""
echo "============================================"
echo " Bucket + CloudFront created."
echo " CloudFront domain : ${DIST_DOMAIN}"
echo " Distribution ID   : ${DIST_ID}"
echo "============================================"
echo ""
echo "Save these for release.sh:"
echo "  export HOP_TAP_CDN_DOMAIN=\"${DIST_DOMAIN}\""
echo "  export HOP_TAP_CF_DISTRIBUTION_ID=\"${DIST_ID}\""
echo ""
echo "Next steps (semi-manual; need ACM validation wait):"
echo ""
echo "  # 1. Request the cert in us-east-1 (CloudFront requires it there):"
echo "  aws acm request-certificate \\"
echo "    --domain-name tap.keik.ai \\"
echo "    --validation-method DNS \\"
echo "    --region us-east-1"
echo ""
echo "  # 2. Read the validation CNAME from the cert and add it to Route 53"
echo "  #    (the keik.ai zone). Wait ~1-5 min for ACM to mark it Issued."
echo ""
echo "  # 3. Attach Aliases + ViewerCertificate to the distribution:"
echo "  aws cloudfront update-distribution \\"
echo "    --id ${DIST_ID} \\"
echo "    --if-match <ETag from get-distribution-config> \\"
echo "    --distribution-config <updated config with Aliases + ViewerCertificate>"
echo ""
echo "  # 4. Add Route 53 A/AAAA alias records for tap.keik.ai →"
echo "  #    ${DIST_DOMAIN}"
