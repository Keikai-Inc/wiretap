#!/usr/bin/env bash
# setup-ci-release.sh — one-time setup so GitHub CI can publish signed WireTap
# releases. Run locally, once, with `gh` authed (admin on Keikai-Inc/wiretap)
# and AWS credentials for account 064311028681. Idempotent.
#
#   ./scripts/setup-ci-release.sh
#
# It: (1) uploads the release secrets, (2) extends the shared OIDC role so
# wiretap's `release` environment can assume it and write to the tap bucket,
# and (3) reminds you of the manual steps (release environment, toolchain image,
# pubkey embed).
set -euo pipefail

REPO="Keikai-Inc/wiretap"
ROLE="wirehop-github-release"
ACCOUNT="064311028681"
KEY="${HOME}/.hop-signing/hop-release-private.pem"
TAP_BUCKET="hop-tap-releases"
TAP_CF="E3RUDMOZYC7OMX"

command -v gh  >/dev/null || { echo "need gh"  >&2; exit 1; }
command -v aws >/dev/null || { echo "need aws" >&2; exit 1; }
command -v jq  >/dev/null || { echo "need jq"  >&2; exit 1; }
[ -f "$KEY" ] || { echo "signing key not found: $KEY" >&2; exit 1; }

echo "==> 1/3 secrets on $REPO"
gh secret set HOP_SIGNING_KEY_PEM        --repo "$REPO" < "$KEY"
gh secret set AWS_ROLE_ARN               --repo "$REPO" --body "arn:aws:iam::${ACCOUNT}:role/${ROLE}"
gh secret set HOP_TAP_CF_DISTRIBUTION_ID --repo "$REPO" --body "$TAP_CF"
gh secret list --repo "$REPO"

echo "==> 2/3 extend the OIDC role trust to wiretap's release environment"
trust="$(aws iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument' --output json)"
sub="repo:${REPO}:environment:release"
if grep -q "$sub" <<<"$trust"; then
  echo "    trust already allows $sub"
else
  new="$(jq --arg s "$sub" '
    .Statement[0].Condition.StringLike["token.actions.githubusercontent.com:sub"] += [$s]' <<<"$trust")"
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "$new"
  echo "    added $sub to the trust policy"
fi

echo "==> 3/3 extend the publish policy to the tap bucket + CDN"
pol="$(aws iam get-role-policy --role-name "$ROLE" --policy-name wirehop-release-publish --query 'PolicyDocument' --output json)"
if grep -q "$TAP_BUCKET" <<<"$pol"; then
  echo "    policy already covers $TAP_BUCKET"
else
  new="$(jq --arg b "$TAP_BUCKET" --arg cf "arn:aws:cloudfront::${ACCOUNT}:distribution/${TAP_CF}" '
    .Statement[0].Resource = [.Statement[0].Resource, "arn:aws:s3:::\($b)/*"]
    | .Statement[1].Resource = [.Statement[1].Resource, "arn:aws:s3:::\($b)"]
    | .Statement[2].Resource = [.Statement[2].Resource, $cf]' <<<"$pol")"
  aws iam put-role-policy --role-name "$ROLE" --policy-name wirehop-release-publish --policy-document "$new"
  echo "    added $TAP_BUCKET + tap CDN to wirehop-release-publish"
fi

cat <<'NOTE'

==> Manual steps left (GitHub UI / follow-up):
  - Create a `release` environment on Keikai-Inc/wiretap with yourself as a
    required reviewer (Settings -> Environments). The OIDC trust is scoped to it,
    so the publish job can only assume the role after your approval.
  - Build the toolchain image once: Actions -> "eBPF toolchain image" -> Run.
    Then set the repo variable HOP_TAP_TOOLCHAIN_IMAGE and (after the first
    signed release) HOP_TAP_EBPF_URL to turn on the gated CI lanes in ci.yml.
  - After the first signed release publishes .sig files, embed the release
    public key in install.sh (set HOP_TAP_PUBKEY to the contents of
    ~/.hop-signing/hop-release-public.pem) to make installs fail-closed.
  - Tag a release to run it:  git tag v0.2.31 && git push origin v0.2.31
NOTE
echo "done."
