/**
 * First-run onboarding: bootstrap → choose recommended lists → apply with progress.
 */
const brw = typeof browser !== 'undefined' ? browser : chrome;

/** Former silent defaults — now the Recommended pack. */
const RECOMMENDED_LISTS = [
    { id: 'easylist', name: 'EasyList', blurb: 'Core ad blocking' },
    { id: 'easyprivacy', name: 'EasyPrivacy', blurb: 'Trackers & beacons' },
    { id: 'peter_lowe', name: 'Peter Lowe', blurb: 'Ads & trackers (compact)' },
    { id: 'ublock_filters', name: 'uBlock filters', blurb: 'Extra ad / tracker coverage' },
    { id: 'adguard_ubo', name: 'AdGuard/uBO Tracking', blurb: 'URL tracking protection' },
    { id: 'ublock_badware', name: 'uBlock Badware', blurb: 'Risky / malicious sites' },
    { id: 'malicious_url', name: 'Malicious URL Blocklist', blurb: 'Known malware URLs' }
];

const MINIMAL_IDS = ['easylist', 'easyprivacy', 'ublock_badware'];

const $ = (id) => document.getElementById(id);

function setStep(name) {
    document.querySelectorAll('[data-step]').forEach((el) => {
        el.hidden = el.dataset.step !== name;
    });
}

function selectedIds() {
    return [...document.querySelectorAll('.list-check:checked')].map((el) => el.value);
}

function applyPreset(ids) {
    const set = new Set(ids);
    document.querySelectorAll('.list-check').forEach((el) => {
        el.checked = set.has(el.value);
    });
    updateCount();
}

function updateCount() {
    const n = selectedIds().length;
    const el = $('sel-count');
    if (el) el.textContent = String(n);
}

async function bootstrap() {
    setStep('loading');
    const status = $('loading-status');
    const detail = $('loading-detail');

    try {
        status.textContent = 'Preparing OPSECHub…';
        detail.textContent = 'Clearing temporary state and starting the engine.';
        await new Promise((r) => setTimeout(r, 400));

        status.textContent = 'Fetching filter catalog from Git…';
        detail.textContent = 'This only downloads the list of available filters — not every list yet.';
        const cat = await brw.runtime.sendMessage({ action: 'refreshRemoteCatalog' }).catch(() => null);

        status.textContent = 'Almost ready…';
        detail.textContent = (cat && cat.success === false) || cat?.ok === false
            ? 'Using the bundled catalog offline. You can refresh later from Settings.'
            : 'Catalog ready. Choose what to enable.';
        await new Promise((r) => setTimeout(r, 500));
    } catch (err) {
        console.warn(err);
        detail.textContent = 'Continuing with local defaults. You can refresh lists later.';
        await new Promise((r) => setTimeout(r, 600));
    }

    renderListPicker();
    setStep('choose');
}

function renderListPicker() {
    const box = $('list-picker');
    if (!box) return;
    box.innerHTML = '';
    for (const item of RECOMMENDED_LISTS) {
        const row = document.createElement('label');
        row.className = 'list-row';
        row.innerHTML = `
            <input type="checkbox" class="list-check" value="${item.id}" checked>
            <span class="list-text">
                <strong>${item.name}</strong>
                <span class="list-blurb">${item.blurb}</span>
            </span>
            <span class="list-badge">Recommended</span>
        `;
        box.appendChild(row);
    }
    box.querySelectorAll('.list-check').forEach((el) => {
        el.addEventListener('change', updateCount);
    });
    updateCount();
}

async function applySelection(ids) {
    setStep('applying');
    const bar = $('apply-bar');
    const status = $('apply-status');
    const detail = $('apply-detail');

    const store = await brw.storage.local.get({ moduleStates: {} });
    const states = { ...(store.moduleStates || {}) };

    if (ids.length === 0) {
        status.textContent = 'Finishing setup…';
        detail.textContent = 'No lists selected — AdBlocker stays off until you enable lists in Settings.';
        if (bar) bar.style.width = '100%';
        states.adBlocker = false;
        await brw.storage.local.set({
            enabledFilterLists: [],
            setupCompleted: true,
            moduleStates: states
        });
        await brw.runtime.sendMessage({ action: 'toggleModule', module: 'adBlocker', enabled: false }).catch(() => { });
        await new Promise((r) => setTimeout(r, 500));
        setStep('done');
        return;
    }

    // Mark AdBlocker on in storage first so list installs are allowed, then download.
    states.adBlocker = true;
    await brw.storage.local.set({
        enabledFilterLists: [],
        setupCompleted: false,
        moduleStates: states
    });

    let done = 0;
    let failed = 0;
    for (const id of ids) {
        const meta = RECOMMENDED_LISTS.find((x) => x.id === id);
        status.textContent = `Loading ${meta?.name || id}…`;
        detail.textContent = `Downloading rules from Git (${done + 1} / ${ids.length}). This can take a moment.`;
        if (bar) bar.style.width = `${Math.round((done / ids.length) * 100)}%`;

        try {
            const res = await brw.runtime.sendMessage({
                action: 'toggleDynamicList',
                listId: id,
                enabled: true
            });
            if (!res || !res.success) failed += 1;
        } catch {
            failed += 1;
        }
        done += 1;
        if (bar) bar.style.width = `${Math.round((done / ids.length) * 100)}%`;
    }

    await brw.storage.local.set({ setupCompleted: true });
    // Final sync (lists already installed — resumes from cache quickly).
    await brw.runtime.sendMessage({ action: 'toggleModule', module: 'adBlocker', enabled: true }).catch(() => { });
    status.textContent = failed ? 'Setup finished with some errors' : 'All set!';
    detail.textContent = failed
        ? `${done - failed} lists loaded, ${failed} failed (you can retry from Settings).`
        : `${done} filter lists are active.`;
    await new Promise((r) => setTimeout(r, 700));
    setStep('done');
}

function wireUi() {
    $('btn-preset-recommended')?.addEventListener('click', () => {
        applyPreset(RECOMMENDED_LISTS.map((x) => x.id));
    });
    $('btn-preset-minimal')?.addEventListener('click', () => {
        applyPreset(MINIMAL_IDS);
    });
    $('btn-preset-none')?.addEventListener('click', () => {
        applyPreset([]);
    });

    $('btn-apply')?.addEventListener('click', () => {
        applySelection(selectedIds());
    });
    $('btn-skip')?.addEventListener('click', () => {
        if (confirm('Continue without filter lists? AdBlocker will stay off until you select at least one list in Settings.')) {
            applySelection([]);
        }
    });

    $('btn-open-options')?.addEventListener('click', () => {
        const url = brw.runtime.getURL('options.html?cat=security&tool=opt-adblocker');
        brw.tabs.create({ url });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    wireUi();
    bootstrap();
});
