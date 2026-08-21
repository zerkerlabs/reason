(() => {
  'use strict';

  const install = () => {
  const brand = document.querySelector('[data-zk-product-brand], .nav .brand, .masthead__inner > .mark');
  if (!brand) return false;
  if (brand.closest('.zk-product-family')) return true;

  const path = window.location.pathname.replace(/\/$/, '') || '/';
  const current = path === '/reason' || path.startsWith('/reason/')
    ? 'Reason'
    : path === '/guard' || path.startsWith('/guard/')
      ? 'Guard'
      : 'Gateway';
  const uid = `zk-products-${Math.random().toString(36).slice(2, 9)}`;
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
  trigger.innerHTML = `<span>${current}</span><svg viewBox="0 0 10 6" aria-hidden="true"><path d="m1 1 4 4 4-4"/></svg>`;
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
      <a class="zk-product-row" href="${productBase}/" data-product="Gateway">
        <span class="zk-product-icon zk-product-icon--gateway" aria-hidden="true"></span>
        <span class="zk-product-copy"><strong>Gateway</strong><small>Route and govern agent traffic</small></span>
        <span class="zk-product-state">Available</span>
      </a>
      <a class="zk-product-row" href="${productBase}/reason" data-product="Reason">
        <span class="zk-product-icon zk-product-icon--reason" aria-hidden="true">∴</span>
        <span class="zk-product-copy"><strong>Reason</strong><small>Verify exact actions before execution</small></span>
        <span class="zk-product-state">v0.2</span>
      </a>
      <a class="zk-product-row" href="${productBase}/guard" data-product="Guard">
        <span class="zk-product-icon zk-product-icon--guard" aria-hidden="true">G</span>
        <span class="zk-product-copy"><strong>Guard</strong><small>Control agent egress on-device</small></span>
        <span class="zk-product-state">macOS</span>
      </a>
    </div>
    <div class="zk-related">
      <p>Related systems</p>
      <div>
        <a href="https://zmem.sh"><span><strong>ZMem</strong><small>Govern agent memory</small></span><b aria-hidden="true">↗</b></a>
        <a href="https://treeship.dev"><span><strong>Treeship</strong><small>Sign receipts for captured work</small></span><b aria-hidden="true">↗</b></a>
      </div>
    </div>`;
  family.appendChild(panel);

  const closeButton = panel.querySelector('.zk-product-close');
  const rows = Array.from(panel.querySelectorAll('.zk-product-row'));
  const currentRow = rows.find((row) => row.dataset.product === current);
  if (currentRow) {
    currentRow.classList.add('is-current');
    currentRow.setAttribute('aria-current', 'page');
    currentRow.querySelector('.zk-product-state').textContent = 'Current';
  }

  let open = false;
  let returnFocus = false;
  const isSheet = () => window.matchMedia('(max-width: 720px)').matches;
  const focusable = () => Array.from(panel.querySelectorAll('a[href], button:not([disabled])'));

  const setOpen = (next, options = {}) => {
    if (next === open) return;
    open = next;
    returnFocus = Boolean(options.returnFocus);
    family.dataset.open = String(next);
    document.documentElement.classList.toggle('zk-switcher-open', next);
    trigger.setAttribute('aria-expanded', String(next));
    panel.setAttribute('aria-hidden', String(!next));
    panel.setAttribute('aria-modal', String(next && isSheet()));
    backdrop.tabIndex = next && isSheet() ? 0 : -1;

    if (next) {
      window.requestAnimationFrame(() => (currentRow || rows[0] || closeButton).focus());
    } else if (returnFocus) {
      trigger.focus();
    }
  };

  trigger.addEventListener('click', () => setOpen(!open, { returnFocus: true }));
  closeButton.addEventListener('click', () => setOpen(false, { returnFocus: true }));
  backdrop.addEventListener('click', () => setOpen(false, { returnFocus: true }));
  rows.forEach((row) => row.addEventListener('click', () => setOpen(false)));

  document.addEventListener('pointerdown', (event) => {
    if (open && !isSheet() && !family.contains(event.target)) setOpen(false);
  });

  document.addEventListener('keydown', (event) => {
    if (!open) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false, { returnFocus: true });
      return;
    }
    if (event.key !== 'Tab' || !isSheet()) return;
    const items = focusable();
    if (!items.length) return;
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
