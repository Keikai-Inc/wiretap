(function () {
  var NAV_LINKS = [
    { label: 'Commands',     href: '#commands',  cross: 'index.html#commands' },
    { label: 'Demo',         href: '#takedown',  cross: 'index.html#takedown' },
    { label: 'Why',          href: '#why',       cross: 'index.html#why' },
    { label: 'Install',      href: '#install',   cross: 'index.html#install' },
    { label: 'Permissions',  href: '#perms',     cross: 'index.html#perms' },
    { label: 'Remote / AI',  href: 'remote.html', cross: 'remote.html' },
  ];

  var path = location.pathname;
  var onIndex = path === '/' || path.endsWith('/index.html') || path.endsWith('/index') || /\/site\/?$/.test(path);

  /* --- Nav --------------------------------------------------------------- */
  var navEl = document.getElementById('site-nav');
  if (navEl) {
    var items = NAV_LINKS.map(function (link) {
      var url = (onIndex || !link.href.startsWith('#')) ? link.href : link.cross;
      var cls = '';
      if (!onIndex && link.href === 'remote.html' && path.indexOf('remote') !== -1) cls = ' class="active"';
      return '<li><a href="' + url + '"' + cls + '>' + link.label + '</a></li>';
    }).join('');

    navEl.innerHTML =
      '<a href="index.html" class="nav-brand">tap</a>' +
      '<button class="nav-toggle" aria-label="Toggle navigation" ' +
        'onclick="document.querySelector(\'.nav-links\').classList.toggle(\'open\')">' +
        '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
          '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>' +
        '</svg>' +
      '</button>' +
      '<ul class="nav-links">' + items + '</ul>';
  }

  /* --- Footer ------------------------------------------------------------ */
  var footerEl = document.getElementById('site-footer');
  if (footerEl) {
    footerEl.innerHTML =
      '<div class="footer-bottom">' +
        '<p class="footer-copy">&copy; 2026 <a href="https://keik.ai">Keik.ai</a> Cybersecurity. ' +
          'tap is the missing Linux administrator command. ' +
          'Optional integration with <a href="https://hop.keik.ai">hop</a> for remote and AI access.</p>' +
      '</div>';
  }
})();
