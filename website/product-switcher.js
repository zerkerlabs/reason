(() => {
  'use strict';

  const install = () => {
    const brand = document.querySelector('[data-zk-product-brand], .nav .brand, .masthead__inner > .mark');
    if (!brand) return false;
    if (brand.closest('.zk-product-family')) return true;

    const uid = `zk-products-${Math.random().toString(36).slice(2, 9)}`;
    const currentPath = window.location.pathname.replace(/\/$/, '');
    const onPlatformHome = currentPath === '';
    const onReasonPage = currentPath === '/reason' || currentPath.startsWith('/reason/');
    const productBase = /^(localhost|127\.0\.0\.1)$/.test(window.location.hostname)
      ? window.location.origin
      : 'https://zerker.ai';

    const family = document.createElement('div');
    family.className = 'zk-product-family';
    family.dataset.productFamily = '';
    brand.parentNode.insertBefore(family, brand);
    family.appendChild(brand);

    const divider = document.createElement('span');
    divider.className = 'zk-product-divider';
    divider.setAttribute('aria-hidden', 'true');
    family.appendChild(divider);

    const trigger = document.createElement('button');
    trigger.className = 'zk-product-trigger';
    trigger.type = 'button';
    trigger.setAttribute('aria-expanded', 'false');
    trigger.setAttribute('aria-controls', uid);
    trigger.setAttribute('aria-label', 'Switch Zerker product');
    trigger.innerHTML = `<span>${onReasonPage ? 'Reason' : onPlatformHome ? 'Platform' : 'Gateway'}</span><svg viewBox="0 0 10 6" aria-hidden="true"><path d="m1 1 4 4 4-4"/></svg>`;
    family.appendChild(trigger);

    const backdrop = document.createElement('button');
    backdrop.className = 'zk-product-backdrop';
    backdrop.type = 'button';
    backdrop.tabIndex = -1;
    backdrop.setAttribute('aria-label', 'Close product switcher');
    document.body.appendChild(backdrop);

    const panel = document.createElement('div');
    panel.className = 'zk-product-panel';
    panel.id = uid;
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'false');
    panel.setAttribute('aria-labelledby', `${uid}-title`);
    panel.setAttribute('aria-hidden', 'true');
    panel.innerHTML = `
      <div class="zk-product-panel__top">
        <p id="${uid}-title">Zerker products</p>
        <button class="zk-product-close" type="button" aria-label="Close product switcher">
          <svg viewBox="0 0 12 12" aria-hidden="true"><path d="m2 2 8 8M10 2 2 10"/></svg>
        </button>
      </div>
      <div class="zk-product-list">
        <a class="zk-product-row" href="${productBase}/#gateway">
          <span class="zk-product-icon zk-product-icon--gateway" aria-hidden="true"></span>
          <span class="zk-product-copy"><strong>Agent Gateway</strong><small>Control identity, policy, routing, and measurement</small></span>
        </a>
        <a class="zk-product-row" href="${productBase}/#console">
          <span class="zk-product-icon zk-product-icon--console" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 15h3M13 13l2 2 3-3"/></svg></span>
          <span class="zk-product-copy"><strong>Operator Console</strong><small>Operate internal and external agent activity</small></span>
        </a>
        <a class="zk-product-row" href="${productBase}/#portals">
          <span class="zk-product-icon zk-product-icon--portals" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="4"/><path d="M9 15 16 8M10 8h6v6"/></svg></span>
          <span class="zk-product-copy"><strong>Agent Portals</strong><small>Deliver agents to partners and customers</small></span>
        </a>
      </div>`;
    family.appendChild(panel);

    const closeButton = panel.querySelector('.zk-product-close');
    const rows = Array.from(panel.querySelectorAll('.zk-product-row'));
    if (!onPlatformHome && !onReasonPage) {
      rows[0].classList.add('is-current');
      rows[0].setAttribute('aria-current', 'page');
    }
    let open = false;
    const isSheet = () => window.matchMedia('(max-width: 720px)').matches;
    const focusable = () => Array.from(panel.querySelectorAll('a[href], button:not([disabled])'));

    const setOpen = (next, returnFocus = false) => {
      if (next === open) return;
      open = next;
      family.dataset.open = String(next);
      document.documentElement.classList.toggle('zk-switcher-open', next);
      trigger.setAttribute('aria-expanded', String(next));
      panel.setAttribute('aria-hidden', String(!next));
      panel.setAttribute('aria-modal', String(next && isSheet()));
      backdrop.tabIndex = next && isSheet() ? 0 : -1;

      if (next) {
        window.setTimeout(() => {
          if (open) rows[0].focus({ preventScroll: true });
        }, 200);
      } else if (returnFocus) {
        trigger.focus();
      }
    };

    trigger.addEventListener('click', () => setOpen(!open, true));
    closeButton.addEventListener('click', () => setOpen(false, true));
    backdrop.addEventListener('click', () => setOpen(false, true));
    rows.forEach((row) => row.addEventListener('click', () => setOpen(false)));

    document.addEventListener('pointerdown', (event) => {
      if (open && !isSheet() && !family.contains(event.target)) setOpen(false);
    });

    document.addEventListener('keydown', (event) => {
      if (!open) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        setOpen(false, true);
        return;
      }
      if (event.key !== 'Tab' || !isSheet()) return;
      const items = focusable();
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    window.addEventListener('resize', () => {
      if (open) panel.setAttribute('aria-modal', String(isSheet()));
    });

    document.documentElement.classList.add('zk-product-family-ready');
    return true;
  };

  if (!install()) {
    const observer = new MutationObserver(() => {
      if (install()) observer.disconnect();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    window.addEventListener('load', () => {
      if (install()) observer.disconnect();
    }, { once: true });
  }
})();
