/**
 * Centered loading modal for filter-list operations (options + popup).
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

let modalEl = null;
let progressListener = null;

function ensureModal() {
    if (typeof document === 'undefined') return null;
    if (modalEl && document.body.contains(modalEl)) return modalEl;

    modalEl = document.createElement('div');
    modalEl.id = 'opsec-filter-busy-modal';
    modalEl.className = 'filter-busy-opt';
    modalEl.style.display = 'none';
    modalEl.setAttribute('aria-live', 'polite');
    modalEl.innerHTML =
        '<div class="filter-busy-modal">' +
        '<div class="filter-busy-card">' +
        '<div class="filter-busy-inner">' +
        '<span class="filter-spinner" aria-hidden="true"></span>' +
        '<span class="filter-busy-text">Working…</span>' +
        '<span class="filter-busy-sub">Please wait.</span>' +
        '</div></div></div>';
    document.body.appendChild(modalEl);
    return modalEl;
}

export function showFilterBusy(title, sub) {
    const el = ensureModal();
    if (!el) return;
    const t = el.querySelector('.filter-busy-text');
    const s = el.querySelector('.filter-busy-sub');
    if (t) t.textContent = title || 'Working…';
    if (s) s.textContent = sub || 'Please wait.';
    el.style.display = 'block';
}

export function updateFilterBusy(title, sub) {
    const el = modalEl || document.getElementById('opsec-filter-busy-modal');
    if (!el) return;
    if (title != null) {
        const t = el.querySelector('.filter-busy-text');
        if (t) t.textContent = title;
    }
    if (sub != null) {
        const s = el.querySelector('.filter-busy-sub');
        if (s) s.textContent = sub;
    }
}

export function hideFilterBusy(delayMs = 0) {
    const el = modalEl || document.getElementById('opsec-filter-busy-modal');
    if (!el) return;
    const hide = () => { el.style.display = 'none'; };
    if (delayMs > 0) setTimeout(hide, delayMs);
    else hide();
}

function applyProgressToModal(p) {
    if (!p || p.active === false) return;
    const total = p.total || 0;
    const current = p.current || 0;
    const phaseLabel = p.phase === 'removing' ? 'Removing lists' : 'Loading lists';
    updateFilterBusy(
        p.title || `${phaseLabel} ${current} / ${total}`,
        p.detail || (total ? `${current} of ${total}` : 'Please wait.')
    );
}

/**
 * Live-update the busy modal from background `listApplyProgress` writes.
 * Returns an unbind function — call it when the operation finishes.
 */
export function bindFilterBusyProgress() {
    if (progressListener) {
        try { brw.storage.onChanged.removeListener(progressListener); } catch { /* ignore */ }
        progressListener = null;
    }

    progressListener = (changes, area) => {
        if (area !== 'local' || !changes.listApplyProgress) return;
        applyProgressToModal(changes.listApplyProgress.newValue);
    };
    brw.storage.onChanged.addListener(progressListener);

    brw.storage.local.get({ listApplyProgress: null }).then(({ listApplyProgress: p }) => {
        applyProgressToModal(p);
    }).catch(() => { });

    return () => {
        if (progressListener) {
            try { brw.storage.onChanged.removeListener(progressListener); } catch { /* ignore */ }
            progressListener = null;
        }
    };
}
