/*******************************************************************************
 * Remote filter lists — fetch catalog + DNR/cosmetics/scriptlet-meta from
 * GitHub (jsDelivr), cache locally, refresh every 24h, never break offline.
 ******************************************************************************/

const brw = typeof browser !== 'undefined' ? browser : chrome;

// Published GitHub layout is `remote-lists/` at repo root (catalog.json lives there).
export const DEFAULT_CDN_BASE =
    'https://cdn.jsdelivr.net/gh/tomsec8/OPSECHub-Lists@main/remote-lists';

const CDN_BASE_FALLBACKS = [
    DEFAULT_CDN_BASE,
    'https://cdn.jsdelivr.net/gh/tomsec8/OPSECHub-Lists@main',
    'https://raw.githubusercontent.com/tomsec8/OPSECHub-Lists/main/remote-lists',
    'https://raw.githubusercontent.com/tomsec8/OPSECHub-Lists/main'
];

/** Chrome MV3 DNR ceilings (filter lists share the dynamic pool). */
export const MAX_DYNAMIC_RULES = 30000;
export const MAX_UNSAFE_DYNAMIC_RULES = 5000;
export const MAX_REGEX_RULES = 1000;
/** Leave room for session/module DNR (headers, exclusions, markers…). */
export const SESSION_HEADROOM = 64;

const RULE_ID_FLOOR = 100000;
const RULE_ID_CEILING = RULE_ID_FLOOR + MAX_DYNAMIC_RULES - 1;
const REGEX_RULE_ID_BASE = 700000;

const RESOURCE_TYPES = [
    'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
    'object', 'xmlhttprequest', 'ping', 'websocket', 'media', 'other'
];

function isUnsafeAction(action) {
    const t = action?.type;
    return t === 'redirect' || t === 'modifyHeaders'
        || !!(action?.requestHeaders || action?.responseHeaders);
}

function countUnsafeRules(rules) {
    let n = 0;
    for (const r of rules || []) {
        if (isUnsafeAction(r.action)) n += 1;
    }
    return n;
}

/**
 * Live Chrome DNR usage — authoritative budget snapshot.
 * Dynamic + session share the ~30k pool; regex/unsafe are sub-caps.
 */
export async function getDnrBudgetSnapshot() {
    const [dynamic, session] = await Promise.all([
        brw.declarativeNetRequest.getDynamicRules().catch(() => []),
        brw.declarativeNetRequest.getSessionRules().catch(() => [])
    ]);
    const dyn = Array.isArray(dynamic) ? dynamic : [];
    const ses = Array.isArray(session) ? session : [];

    let regex = 0;
    let unsafe = 0;
    let filterListRules = 0;
    for (const r of dyn) {
        if (r.condition?.regexFilter) regex += 1;
        if (isUnsafeAction(r.action)) unsafe += 1;
        if (
            (r.id >= RULE_ID_FLOOR && r.id <= RULE_ID_CEILING)
            || (r.id >= REGEX_RULE_ID_BASE && r.id < REGEX_RULE_ID_BASE + MAX_REGEX_RULES)
        ) {
            filterListRules += 1;
        }
    }
    for (const r of ses) {
        if (isUnsafeAction(r.action)) unsafe += 1;
    }

    const total = dyn.length + ses.length;
    const filterBudget = Math.max(0, MAX_DYNAMIC_RULES - SESSION_HEADROOM);

    return {
        dynamic: dyn.length,
        session: ses.length,
        total,
        regex,
        unsafe,
        filterListRules,
        limits: {
            dynamic: MAX_DYNAMIC_RULES,
            unsafe: MAX_UNSAFE_DYNAMIC_RULES,
            regex: MAX_REGEX_RULES,
            filterBudget
        },
        free: {
            dynamic: Math.max(0, MAX_DYNAMIC_RULES - total),
            filter: Math.max(0, filterBudget - filterListRules),
            unsafe: Math.max(0, MAX_UNSAFE_DYNAMIC_RULES - unsafe),
            regex: Math.max(0, MAX_REGEX_RULES - regex)
        }
    };
}

/**
 * Estimate cost of enabling a list (catalog stats or payload length).
 * Returns null if OK, or { error, code, ... } if it would exceed a cap.
 */
export async function wouldExceedDnrBudget(list, { ruleCount = null, regexCount = null, unsafeCount = 0 } = {}) {
    const snap = await getDnrBudgetSnapshot();
    const addRules = ruleCount != null
        ? ruleCount
        : (list?.stats?.compressed ?? 0);
    const addRegex = regexCount != null
        ? regexCount
        : (list?.stats?.regex ?? 0);
    const addUnsafe = unsafeCount || 0;

    // Enabling replaces an existing install of the same list — free its current slot.
    const d = await storageGet({ threatCounts: {}, remoteManagedLists: {} });
    const already = (d.remoteManagedLists || {})[list?.id]
        ? (Number((d.threatCounts || {})[list.id]) || 0)
        : 0;

    const nextFilter = snap.filterListRules - already + addRules + addRegex;
    if (nextFilter > snap.limits.filterBudget) {
        return {
            error: `Dynamic DNR budget exceeded (${nextFilter.toLocaleString()} / ${snap.limits.filterBudget.toLocaleString()}). Disable other lists first.`,
            code: 'dynamic_budget',
            snap,
            nextFilter,
            addRules
        };
    }

    const nextTotal = snap.total - already + addRules + addRegex;
    if (nextTotal > MAX_DYNAMIC_RULES) {
        return {
            error: `Chrome dynamic+session rule limit exceeded (${nextTotal.toLocaleString()} / ${MAX_DYNAMIC_RULES.toLocaleString()}).`,
            code: 'dynamic_hard',
            snap
        };
    }

    if (snap.regex + addRegex > MAX_REGEX_RULES) {
        return {
            error: `Regex rule budget exceeded (~${(snap.regex + addRegex).toLocaleString()} / ${MAX_REGEX_RULES.toLocaleString()}). Disable other regex-heavy lists.`,
            code: 'regex_budget',
            snap,
            nextRegex: snap.regex + addRegex
        };
    }

    if (addUnsafe && snap.unsafe + addUnsafe > MAX_UNSAFE_DYNAMIC_RULES) {
        return {
            error: `Unsafe dynamic rule budget exceeded (${snap.unsafe + addUnsafe} / ${MAX_UNSAFE_DYNAMIC_RULES}).`,
            code: 'unsafe_budget',
            snap
        };
    }

    return null;
}

function normalizeBase(url) {
    return String(url || DEFAULT_CDN_BASE).replace(/\/$/, '');
}

/** Fingerprint a catalog entry so we can skip re-downloading unchanged bodies. */
export function listRevision(list) {
    if (!list) return '';
    const s = list.stats || {};
    return [
        list.id,
        list.remotePath || list.path || '',
        s.original ?? '',
        s.compressed ?? '',
        s.regex ?? '',
        s.css?.generic ?? '',
        s.css?.specific ?? '',
        list.cosmetics || '',
        list.regex || ''
    ].join('|');
}

function catalogBaseCandidates(preferred) {
    const out = [];
    const push = (u) => {
        const n = normalizeBase(u);
        if (n && !out.includes(n)) out.push(n);
    };
    push(preferred);
    for (const u of CDN_BASE_FALLBACKS) push(u);
    // If someone stored the repo root, also try the nested publish folder.
    for (const base of [...out]) {
        if (!/\/remote-lists$/i.test(base)) push(`${base}/remote-lists`);
    }
    return out;
}

async function storageGet(defaults) {
    return brw.storage.local.get(defaults);
}

async function storageSet(obj) {
    return brw.storage.local.set(obj);
}

/** UI-facing progress for multi-list load / unload (popup, options listen via storage). */
async function setListApplyProgress(partial) {
    await storageSet({
        listApplyProgress: {
            active: true,
            updatedAt: Date.now(),
            ...partial
        }
    });
}

async function clearListApplyProgress(extra = {}) {
    await storageSet({
        listApplyProgress: {
            active: false,
            updatedAt: Date.now(),
            ...extra
        }
    });
}

function listDisplayName(catalog, listId) {
    const list = (catalog?.lists || []).find((l) => l.id === listId);
    return list?.name || list?.title || listId;
}

function collectSelectedListIds(d) {
    const ids = new Set();
    for (const id of d.enabledFilterLists || []) ids.add(id);
    for (const [id, on] of Object.entries(d.threatFeeds || {})) {
        if (on) ids.add(id);
    }
    return ids;
}

/** Serialize catalog refresh + list toggles so they never interleave. */
let remoteListsQueue = Promise.resolve();
function enqueueRemoteListOp(fn) {
    const run = remoteListsQueue.then(fn, fn);
    remoteListsQueue = run.catch(() => { });
    return run;
}

async function fetchJson(url, timeoutMs = 45000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'GET',
            cache: 'no-store',
            signal: ctrl.signal
        });
        if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
        return await res.json();
    } finally {
        clearTimeout(t);
    }
}

/** Bundled fallbacks when Git has never been reached. */
export async function loadBundledCatalog() {
    const listsConfig = await fetch(brw.runtime.getURL('rules/lists_config.json')).then(r => r.json());
    const threat = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'))
        .then(r => r.ok ? r.json() : { entries: [] })
        .catch(() => ({ entries: [] }));

    let cdnBaseUrl = DEFAULT_CDN_BASE;
    try {
        const remote = await fetch(brw.runtime.getURL('rules/remote_catalog.json'))
            .then(r => r.ok ? r.json() : null)
            .catch(() => null);
        if (remote?.cdnBaseUrl) cdnBaseUrl = normalizeBase(remote.cdnBaseUrl);
    } catch { /* ignore */ }

    const categories = {};
    const lists = [];
    for (const [catKey, catData] of Object.entries(listsConfig.categories || {})) {
        categories[catKey] = { label: catData.label || catKey };
        for (const [id, info] of Object.entries(catData.lists || {})) {
            lists.push({
                id,
                name: info.name || id,
                category: catKey,
                type: 'full',
                remotePath: `lists/${id}.dnr.json`,
                cosmetics: `cosmetics/${id}.json`,
                scriptlets: `scriptlets/${id}.json`,
                regex: `lists/${id}.regex.json`,
                stats: info.stats || null,
                exclusiveGroup: info.exclusiveGroup || null,
                enabledByDefault: info.enabled === true,
                bundledStatic: info.bundledStatic === true,
                homeURL: info.homeURL || null
            });
        }
    }
    categories.live = { label: 'Live Threat Intelligence' };
    for (const entry of threat.entries || []) {
        lists.push({
            id: entry.id,
            name: entry.name,
            category: 'live',
            type: 'domain',
            remotePath: `live/${entry.id}.json`,
            sourceUrl: entry.url,
            source: entry.source || null,
            attribution: entry.attribution || null,
            stats: null,
            exclusiveGroup: null,
            enabledByDefault: false
        });
    }

    return {
        schemaVersion: 1,
        builtAt: listsConfig.builtAt || null,
        cdnBaseUrl,
        categories,
        lists,
        source: 'bundled-lists_config'
    };
}

export async function getCachedCatalog() {
    const d = await storageGet({
        remoteCatalogCache: null,
        remoteCatalogMeta: null
    });
    if (d.remoteCatalogCache?.lists?.length) {
        return {
            catalog: d.remoteCatalogCache,
            meta: d.remoteCatalogMeta || {},
            fromCache: true
        };
    }
    const bundled = await loadBundledCatalog();
    return {
        catalog: bundled,
        meta: { builtAt: bundled.builtAt, source: bundled.source, offline: true },
        fromCache: false
    };
}

export async function refreshRemoteCatalog({ force = false } = {}) {
    const prev = await storageGet({
        remoteCatalogCache: null,
        remoteCatalogMeta: null,
        remoteCdnBase: DEFAULT_CDN_BASE
    });
    const preferred = prev.remoteCdnBase || prev.remoteCatalogCache?.cdnBaseUrl || DEFAULT_CDN_BASE;
    const bases = catalogBaseCandidates(preferred);
    let lastErr = null;

    for (const base of bases) {
        try {
            const catalog = await fetchJson(`${base}/catalog.json`);
            if (!catalog?.lists || !Array.isArray(catalog.lists)) {
                throw new Error('Invalid catalog.json');
            }
            // Always pin asset URLs to the base that actually served catalog.json
            // (published folder may be /remote-lists even if catalog.cdnBaseUrl is stale).
            catalog.cdnBaseUrl = base;

            const meta = {
                fetchedAt: new Date().toISOString(),
                builtAt: catalog.builtAt || null,
                source: 'github',
                cdnBaseUrl: catalog.cdnBaseUrl,
                listCount: catalog.lists.length,
                ok: true
            };

            if (
                !force &&
                prev.remoteCatalogCache?.builtAt &&
                prev.remoteCatalogCache.builtAt === catalog.builtAt
            ) {
                await storageSet({
                    remoteCatalogMeta: { ...meta, unchanged: true },
                    remoteCdnBase: base
                });
                return { ok: true, unchanged: true, catalog: prev.remoteCatalogCache, meta };
            }

            await storageSet({
                remoteCatalogCache: catalog,
                remoteCatalogMeta: meta,
                remoteCdnBase: catalog.cdnBaseUrl
            });
            console.log(`[OPSECHub] Remote catalog refreshed (${catalog.lists.length} lists) from ${base}`);
            return { ok: true, unchanged: false, catalog, meta };
        } catch (err) {
            lastErr = err;
        }
    }

    console.warn('[OPSECHub] Remote catalog fetch failed, keeping last good copy:', lastErr?.message || lastErr);
    const fallback = prev.remoteCatalogCache?.lists?.length
        ? prev.remoteCatalogCache
        : await loadBundledCatalog();
    const meta = {
        fetchedAt: new Date().toISOString(),
        builtAt: fallback.builtAt || prev.remoteCatalogMeta?.builtAt || null,
        source: prev.remoteCatalogCache ? 'cache' : (fallback.source || 'bundled'),
        cdnBaseUrl: normalizeBase(preferred),
        ok: false,
        error: String(lastErr?.message || lastErr || 'catalog fetch failed')
    };
    await storageSet({ remoteCatalogMeta: meta });
    if (!prev.remoteCatalogCache?.lists?.length) {
        await storageSet({ remoteCatalogCache: fallback, remoteCdnBase: normalizeBase(preferred) });
    }
    return { ok: false, catalog: fallback, meta, error: meta.error };
}

async function getIdMap() {
    const d = await storageGet({ remoteListIdMap: {} });
    return d.remoteListIdMap || {};
}

async function allocateStartId(listId, needed) {
    const map = await getIdMap();
    const capacity = Math.max(needed, 16);
    if (map[listId] && map[listId].capacity >= capacity) {
        return map[listId].startId;
    }
    let next = RULE_ID_FLOOR;
    for (const [id, entry] of Object.entries(map)) {
        if (id === listId) continue;
        next = Math.max(next, (entry.startId || 0) + (entry.capacity || 0));
    }
    if (next + capacity > RULE_ID_CEILING) {
        throw new Error('Dynamic rule id space exhausted — disable other remote lists');
    }
    map[listId] = { startId: next, capacity, listId };
    await storageSet({ remoteListIdMap: map });
    return next;
}

async function removeRulesForList(listId) {
    const map = await getIdMap();
    const entry = map[listId];
    if (!entry) {
        const legacy = {
            live_fake: 100000,
            live_shortener: 200000,
            live_dyndns: 300000,
            live_badware: 400000
        };
        const base = legacy[listId];
        if (!base) return;
        const existing = await brw.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existing.map(r => r.id).filter(id => id >= base && id < base + 99999);
        if (removeRuleIds.length) {
            await brw.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [] });
        }
        return;
    }
    const existing = await brw.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing
        .map(r => r.id)
        .filter(id => id >= entry.startId && id < entry.startId + entry.capacity);
    if (removeRuleIds.length) {
        await brw.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [] });
    }
}

function sanitizeCondition(condition) {
    const c = { ...(condition || {}) };

    // Chrome allows only ONE of resourceTypes / excludedResourceTypes.
    // Packed lists often use excludedResourceTypes (e.g. skip main_frame);
    // never invent resourceTypes on top of that — that yields:
    // "Rule with id N includes and excludes the same resource."
    const hasExcluded = Array.isArray(c.excludedResourceTypes) && c.excludedResourceTypes.length > 0;
    const hasIncluded = Array.isArray(c.resourceTypes) && c.resourceTypes.length > 0;
    if (hasExcluded) {
        delete c.resourceTypes;
    } else if (!hasIncluded) {
        c.resourceTypes = [...RESOURCE_TYPES];
    } else {
        delete c.excludedResourceTypes;
    }

    // Drop empty include/exclude domain lists (invalid) and remove overlaps.
    for (const [incKey, excKey] of [
        ['requestDomains', 'excludedRequestDomains'],
        ['initiatorDomains', 'excludedInitiatorDomains'],
        ['domains', 'excludedDomains'],
    ]) {
        if (Array.isArray(c[incKey]) && c[incKey].length === 0) delete c[incKey];
        if (Array.isArray(c[excKey]) && c[excKey].length === 0) delete c[excKey];
        if (Array.isArray(c[incKey]) && Array.isArray(c[excKey])) {
            const excluded = new Set(c[excKey]);
            c[incKey] = c[incKey].filter(d => !excluded.has(d));
            if (c[incKey].length === 0) delete c[incKey];
        }
    }

    if (Array.isArray(c.resourceTypes) && c.resourceTypes.length === 0) {
        delete c.resourceTypes;
        if (!c.excludedResourceTypes) c.resourceTypes = [...RESOURCE_TYPES];
    }

    return c;
}

function normalizeRulesPayload(payload, startId) {
    let rules = [];
    if (Array.isArray(payload)) rules = payload;
    else if (Array.isArray(payload?.rules)) rules = payload.rules;
    else throw new Error('Remote list payload has no rules array');

    return rules.map((rule, i) => ({
        id: startId + i,
        priority: rule.priority ?? 100,
        action: rule.action || { type: 'block' },
        condition: sanitizeCondition(rule.condition)
    }));
}

export function resolveAssetUrl(catalog, relPath) {
    if (!relPath) return null;
    if (/^https?:\/\//i.test(relPath)) return relPath;
    const base = normalizeBase(catalog.cdnBaseUrl || DEFAULT_CDN_BASE);
    return `${base}/${String(relPath).replace(/^\//, '')}`;
}

export function resolveListUrl(catalog, list) {
    if (list.remotePath) return resolveAssetUrl(catalog, list.remotePath);
    if (list.sourceUrl) return list.sourceUrl;
    if (list.type === 'domain') return resolveAssetUrl(catalog, `live/${list.id}.json`);
    if (list.type === 'full') return resolveAssetUrl(catalog, `lists/${list.id}.dnr.json`);
    return null;
}

async function applyRemoteCosmetics(catalog, list) {
    const rel = list.cosmetics || `cosmetics/${list.id}.json`;
    const url = resolveAssetUrl(catalog, rel);
    if (!url) return { ok: false, reason: 'no-url' };
    try {
        const data = await fetchJson(url);
        await storageSet({
            [`css.specific.${list.id}`]: data,
            [`remoteCosmetic.${list.id}`]: data
        });
        return { ok: true, fromNetwork: true };
    } catch (err) {
        const cached = await storageGet({ [`remoteCosmetic.${list.id}`]: null });
        const prev = cached[`remoteCosmetic.${list.id}`];
        if (prev) {
            await storageSet({ [`css.specific.${list.id}`]: prev });
            return { ok: true, fromCache: true };
        }
        // Fall back to bundled cosmetic JSON if present
        try {
            const bundled = await fetch(brw.runtime.getURL(`rules/scripting/specific/${list.id}.json`))
                .then(r => (r.ok ? r.json() : null));
            if (bundled) {
                await storageSet({ [`css.specific.${list.id}`]: bundled });
                return { ok: true, fromBundled: true };
            }
        } catch { /* ignore */ }
        return { ok: false, error: err.message || String(err) };
    }
}

async function applyRemoteScriptletMeta(catalog, list) {
    const rel = list.scriptlets || `scriptlets/${list.id}.json`;
    const url = resolveAssetUrl(catalog, rel);
    if (!url) return { ok: false, reason: 'no-url' };
    try {
        const data = await fetchJson(url);
        const d = await storageGet({ remoteScriptletMeta: {} });
        const meta = { ...(d.remoteScriptletMeta || {}) };
        meta[list.id] = {
            fetchedAt: new Date().toISOString(),
            hasScriptlets: !!data.hasScriptlets || !!(data.hosts),
            hosts: data.hosts || null,
            // Optional future field: array of { name, args, hostnames }
            rules: Array.isArray(data.rules) ? data.rules : null,
            note: data.note || null
        };
        await storageSet({ remoteScriptletMeta: meta });
        return { ok: true, fromNetwork: true, hasRules: !!meta[list.id].rules };
    } catch (err) {
        return { ok: false, error: err.message || String(err) };
    }
}

/** Fetch regex companion rules for a full list; cache under remoteRegex.<id>. */
async function applyRemoteRegex(catalog, list) {
    const rel = list.regex || `lists/${list.id}.regex.json`;
    const url = resolveAssetUrl(catalog, rel);
    if (!url) return { ok: false, reason: 'no-url' };
    try {
        const data = await fetchJson(url);
        const rules = Array.isArray(data) ? data : (data.rules || []);
        if (!Array.isArray(rules)) {
            return { ok: false, error: 'regex payload is not an array' };
        }
        await storageSet({
            [`remoteRegex.${list.id}`]: {
                fetchedAt: new Date().toISOString(),
                rules
            }
        });
        return { ok: true, fromNetwork: true, count: rules.length };
    } catch (err) {
        const cached = await storageGet({ [`remoteRegex.${list.id}`]: null });
        if (cached[`remoteRegex.${list.id}`]?.rules) {
            return {
                ok: true,
                fromCache: true,
                count: cached[`remoteRegex.${list.id}`].rules.length
            };
        }
        // Bundled fallback (extension package)
        try {
            const bundled = await fetch(brw.runtime.getURL(`rules/regex/${list.id}.json`))
                .then(r => (r.ok ? r.json() : null));
            if (Array.isArray(bundled)) {
                await storageSet({
                    [`remoteRegex.${list.id}`]: {
                        fetchedAt: new Date().toISOString(),
                        rules: bundled,
                        fromBundled: true
                    }
                });
                return { ok: true, fromBundled: true, count: bundled.length };
            }
        } catch { /* ignore */ }
        return { ok: false, error: err.message || String(err) };
    }
}

/**
 * Load regex rule arrays for enabled list ids (remote cache → bundled).
 * Used by background syncRegexRules.
 */
export async function loadRegexRulesForLists(listIds) {
    const out = [];
    for (const id of listIds || []) {
        const cached = await storageGet({ [`remoteRegex.${id}`]: null });
        const remote = cached[`remoteRegex.${id}`];
        if (Array.isArray(remote?.rules) && remote.rules.length) {
            out.push(...remote.rules);
            continue;
        }
        try {
            const bundled = await fetch(brw.runtime.getURL(`rules/regex/${id}.json`))
                .then(r => (r.ok ? r.json() : []));
            if (Array.isArray(bundled) && bundled.length) out.push(...bundled);
        } catch { /* ignore */ }
    }
    return out;
}

async function clearListSideData(listId) {
    const d = await storageGet({
        remoteManagedLists: {},
        remoteScriptletMeta: {},
        remoteCosmetic: null
    });
    const managed = { ...(d.remoteManagedLists || {}) };
    delete managed[listId];
    const scriptMeta = { ...(d.remoteScriptletMeta || {}) };
    delete scriptMeta[listId];
    await storageSet({ remoteManagedLists: managed, remoteScriptletMeta: scriptMeta });
    try {
        await brw.storage.local.remove([
            `css.specific.${listId}`,
            `remoteCosmetic.${listId}`,
            `remoteRegex.${listId}`
        ]);
    } catch { /* ignore */ }
}

/**
 * Install or clear a remote list (domain or full). Network first; cache offline.
 * Full lists: dynamic DNR + cosmetics + scriptlet meta only (no static rulesets).
 */
export function setRemoteListEnabled(listId, enabled, opts = {}) {
    return enqueueRemoteListOp(() => setRemoteListEnabledNow(listId, enabled, opts));
}

async function setRemoteListEnabledNow(listId, enabled, {
    catalog = null,
    keepSelection = false,
    skipIfUnchanged = false,
    preferCache = false
} = {}) {
    const { catalog: cat } = catalog
        ? { catalog }
        : await getCachedCatalog();
    const list = (cat.lists || []).find(l => l.id === listId);
    if (!list) return { success: false, error: `Unknown list: ${listId}` };

    const d = await storageGet({
        moduleStates: {},
        masterSwitch: true,
        remoteListPayloadCache: {},
        threatFeeds: {},
        threatCounts: {},
        liveListMeta: {},
        enabledFilterLists: [],
        remoteManagedLists: {},
        remoteListRevisions: {}
    });

    const nextRev = listRevision(list);
    if (
        enabled &&
        skipIfUnchanged &&
        d.remoteManagedLists?.[listId] &&
        d.remoteListRevisions?.[listId] === nextRev
    ) {
        return {
            success: true,
            unchanged: true,
            count: d.threatCounts?.[listId] || 0,
            domains: d.liveListMeta?.[listId]?.domains || 0,
            revision: nextRev
        };
    }

    const adOn = d.masterSwitch !== false && d.moduleStates.adBlocker !== false;

    // Drop live DNR but keep the user's checkbox selection. Must invalidate
    // revision / applied markers so turning AdBlocker back on reinstalls rules
    // instead of hitting skipIfUnchanged / catalog fast-path.
    async function suspendRulesKeepSelection() {
        await removeRulesForList(listId);
        const revisions = { ...(d.remoteListRevisions || {}) };
        const counts = { ...(d.threatCounts || {}) };
        delete revisions[listId];
        counts[listId] = 0;
        await storageSet({
            remoteListRevisions: revisions,
            threatCounts: counts,
            remoteListsAppliedBuiltAt: null
        });
        return { success: true, count: 0, domains: 0, cleared: true, keptSelection: true };
    }

    // AdBlocker off: do not install network rules; selection can still change.
    if (!adOn) {
        if (keepSelection) {
            return suspendRulesKeepSelection();
        }
        if (enabled) {
            const feeds = { ...(d.threatFeeds || {}) };
            const enabledLists = new Set(d.enabledFilterLists || []);
            const patch = {};
            if (list.type === 'domain') {
                feeds[listId] = true;
                patch.threatFeeds = feeds;
            } else {
                enabledLists.add(listId);
                patch.enabledFilterLists = Array.from(enabledLists);
            }
            await storageSet(patch);
            return {
                success: true,
                count: 0,
                domains: 0,
                deferred: true,
                mode: 'selection-only'
            };
        }
        await removeRulesForList(listId);
        const feeds = { ...(d.threatFeeds || {}) };
        const counts = { ...(d.threatCounts || {}) };
        const meta = { ...(d.liveListMeta || {}) };
        const revisions = { ...(d.remoteListRevisions || {}) };
        delete feeds[listId];
        delete counts[listId];
        delete meta[listId];
        delete revisions[listId];
        await clearListSideData(listId);
        const patch = {
            threatFeeds: feeds,
            threatCounts: counts,
            liveListMeta: meta,
            remoteListRevisions: revisions
        };
        if (list.type !== 'domain') {
            const enabledLists = new Set(d.enabledFilterLists || []);
            enabledLists.delete(listId);
            patch.enabledFilterLists = Array.from(enabledLists);
        }
        await storageSet(patch);
        return { success: true, count: 0, domains: 0, cleared: true };
    }

    if (!enabled) {
        if (keepSelection) {
            return suspendRulesKeepSelection();
        }
        await removeRulesForList(listId);
        const feeds = { ...(d.threatFeeds || {}) };
        const counts = { ...(d.threatCounts || {}) };
        const meta = { ...(d.liveListMeta || {}) };
        const revisions = { ...(d.remoteListRevisions || {}) };
        delete feeds[listId];
        delete counts[listId];
        delete meta[listId];
        delete revisions[listId];
        await clearListSideData(listId);
        const patch = {
            threatFeeds: feeds,
            threatCounts: counts,
            liveListMeta: meta,
            remoteListRevisions: revisions
        };
        if (list.type !== 'domain') {
            const enabledLists = new Set(d.enabledFilterLists || []);
            enabledLists.delete(listId);
            patch.enabledFilterLists = Array.from(enabledLists);
        }
        await storageSet(patch);
        return { success: true, count: 0, domains: 0, cleared: true };
    }

    const url = resolveListUrl(cat, list);
    const payloads = { ...(d.remoteListPayloadCache || {}) };
    let payload = null;
    let fromNetwork = false;

    // AdBlocker resume: reinstall from local cache first (no re-download).
    if (preferCache && payloads[listId]?.payload) {
        payload = payloads[listId].payload;
    }

    if (!payload && url && /^https?:\/\//.test(url)) {
        try {
            payload = await fetchJson(url);
            payloads[listId] = {
                fetchedAt: new Date().toISOString(),
                url,
                payload
            };
            fromNetwork = true;
            await storageSet({ remoteListPayloadCache: payloads });
        } catch (err) {
            console.warn(`[OPSECHub] Fetch ${listId} failed, trying cache:`, err.message || err);
        }
    }

    if (!payload && payloads[listId]?.payload) {
        payload = payloads[listId].payload;
    }

    if (!payload && list.type === 'domain' && list.sourceUrl) {
        try {
            const text = await fetch(list.sourceUrl, { cache: 'no-store' }).then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.text();
            });
            payload = await compressDomainTextToPayload(listId, text, list.sourceUrl);
            payloads[listId] = { fetchedAt: new Date().toISOString(), url: list.sourceUrl, payload };
            await storageSet({ remoteListPayloadCache: payloads });
            fromNetwork = true;
        } catch (err) {
            return { success: false, error: `No cached rules and fetch failed: ${err.message}` };
        }
    }

    // Full list CRX seed (currently only HaGeZi Pro under Backup).
    if (!payload && list.type === 'full') {
        try {
            const bundled = await fetch(
                brw.runtime.getURL(`rules/bundled/${listId}.json`)
            ).then(r => (r.ok ? r.json() : null));
            if (Array.isArray(bundled) && bundled.length) {
                payload = bundled;
            }
        } catch { /* ignore */ }
    }

    if (!payload && list.type === 'full') {
        return {
            success: false,
            error: 'Remote DNR unavailable (offline and no cached copy). Enable when online.'
        };
    }

    if (!payload) {
        return {
            success: false,
            error: 'No rules available (offline and no cached copy). Try again when online.'
        };
    }

    const rawRules = Array.isArray(payload) ? payload : payload.rules;
    if (!Array.isArray(rawRules) || rawRules.length === 0) {
        return { success: false, error: 'Remote payload contains zero rules' };
    }

    const unsafeInPayload = countUnsafeRules(rawRules);
    const regexEstimate = list.stats?.regex || 0;
    const over = await wouldExceedDnrBudget(list, {
        ruleCount: rawRules.length,
        regexCount: regexEstimate,
        unsafeCount: unsafeInPayload
    });
    if (over) {
        return { success: false, error: over.error, code: over.code, budget: over.snap };
    }

    const startId = await allocateStartId(listId, rawRules.length);
    await removeRulesForList(listId);
    const addRules = normalizeRulesPayload(payload, startId);

    try {
        // Chrome rejects the whole batch if any rule is invalid.
        await brw.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [],
            addRules
        });
    } catch (err) {
        console.error(`[OPSECHub] updateDynamicRules failed for ${listId}:`, err.message || err);
        return { success: false, error: err.message || String(err) };
    }

    // When resuming from cache, keep previously stored cosmetics/regex side data.
    const cosmetics = list.type === 'full'
        ? (preferCache ? { ok: true, reused: true } : await applyRemoteCosmetics(cat, list))
        : { ok: false, skipped: true };
    const scriptlets = list.type === 'full'
        ? (preferCache ? { ok: true, reused: true } : await applyRemoteScriptletMeta(cat, list))
        : { ok: false, skipped: true };
    const regex = list.type === 'full'
        ? (preferCache ? { ok: true, reused: true } : await applyRemoteRegex(cat, list))
        : { ok: false, skipped: true };

    const domains = payload.stats?.domains || 0;
    const feeds = { ...(d.threatFeeds || {}) };
    const counts = { ...(d.threatCounts || {}) };
    const meta = { ...(d.liveListMeta || {}) };
    const managed = { ...(d.remoteManagedLists || {}) };
    const revisions = { ...(d.remoteListRevisions || {}) };

    if (list.type === 'domain') feeds[listId] = true;
    counts[listId] = addRules.length;
    managed[listId] = true;
    revisions[listId] = nextRev;
    meta[listId] = {
        updatedAt: new Date().toISOString(),
        domains,
        rules: addRules.length,
        url,
        fromNetwork,
        mode: 'remote-dynamic',
        revision: nextRev
    };

    const patch = {
        threatFeeds: feeds,
        threatCounts: counts,
        liveListMeta: meta,
        remoteManagedLists: managed,
        remoteListRevisions: revisions
    };
    if (list.type === 'full') {
        const enabledLists = new Set(d.enabledFilterLists || []);
        enabledLists.add(listId);
        patch.enabledFilterLists = Array.from(enabledLists);
    }
    await storageSet(patch);

    return {
        success: true,
        mode: 'remote-dynamic',
        count: addRules.length,
        domains,
        updatedAt: meta[listId].updatedAt,
        fromNetwork,
        fromCache: !fromNetwork,
        cosmetics,
        scriptlets,
        regex,
        revision: nextRev
    };
}

async function compressDomainTextToPayload(listId, text, sourceUrl) {
    const RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
    const domains = new Set();
    let original = 0;
    for (let line of String(text).split('\n')) {
        line = line.trim();
        if (!line || line.startsWith('!') || line.startsWith('[')) continue;
        original += 1;
        if (line.startsWith('@@') || line.includes('##')) continue;
        if (/^(0\.0\.0\.0|127\.0\.0\.1)\s+/.test(line)) {
            line = line.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').trim().split(/\s+/)[0];
        }
        const m = line.match(/^\|\|([a-z0-9.-]+)\^(\$[^,]*)?$/i);
        if (m && RE.test(m[1])) { domains.add(m[1].toLowerCase()); continue; }
        if (!line.includes('$') && !line.includes('*') && !line.includes('/') && !line.includes('|') && RE.test(line)) {
            domains.add(line.toLowerCase());
        }
    }
    const list = Array.from(domains);
    const CHUNK = 4000;
    const rules = [];
    let id = 1;
    for (let i = 0; i < list.length; i += CHUNK) {
        rules.push({
            id: id++,
            priority: 100,
            action: { type: 'block' },
            condition: { requestDomains: list.slice(i, i + CHUNK), resourceTypes: [...RESOURCE_TYPES] }
        });
    }
    return {
        id: listId,
        kind: 'domain',
        sourceUrl,
        stats: { original, domains: list.length, compressed: rules.length },
        rules
    };
}

export function refreshEnabledRemoteLists(opts = {}) {
    return enqueueRemoteListOp(() => refreshEnabledRemoteListsNow(opts));
}

/** Unload DNR for all selected lists but keep checkboxes (AdBlocker pause). */
export function suspendEnabledRemoteLists() {
    return enqueueRemoteListOp(() => suspendEnabledRemoteListsNow());
}

/**
 * If the browser/extension died mid load/unload, finish the job on next wake.
 * - AdBlocker on + selected lists missing revisions → resume install
 * - AdBlocker off + leftover revisions → finish unload
 */
export function repairIncompleteRemoteLists() {
    return enqueueRemoteListOp(() => repairIncompleteRemoteListsNow());
}

async function refreshEnabledRemoteListsNow({ force = false } = {}) {
    // Catalog: always try network (new list names). Bodies: only when revision changed
    // (unless force — e.g. AdBlocker toggled back on after rules were suspended).
    const catRes = await refreshRemoteCatalog({ force: false });
    const catalog = catRes.catalog;
    const catalogIds = new Set((catalog.lists || []).map(l => l.id));
    const d = await storageGet({
        threatFeeds: {},
        enabledFilterLists: [],
        remoteManagedLists: {},
        remoteListRevisions: {},
        remoteListsAppliedBuiltAt: null,
        moduleStates: {},
        masterSwitch: true
    });
    if (d.masterSwitch === false || d.moduleStates.adBlocker === false) {
        return {
            ok: catRes.ok,
            refreshed: 0,
            skipped: 0,
            catalogOk: catRes.ok,
            unchanged: !!catRes.unchanged,
            meta: catRes.meta
        };
    }

    const toRefresh = new Set();
    for (const [id, on] of Object.entries(d.threatFeeds || {})) {
        if (on && catalogIds.has(id)) toRefresh.add(id);
    }
    for (const id of d.enabledFilterLists || []) {
        if (catalogIds.has(id)) toRefresh.add(id);
    }

    // Fast path: same catalog build + every enabled list already at that revision.
    if (
        !force &&
        catRes.unchanged &&
        catalog.builtAt &&
        d.remoteListsAppliedBuiltAt === catalog.builtAt
    ) {
        await storageSet({
            liveListsLastSync: new Date().toISOString(),
            remoteListsLastSync: new Date().toISOString()
        });
        await clearListApplyProgress();
        return {
            ok: true,
            refreshed: 0,
            skipped: toRefresh.size,
            failed: 0,
            catalogOk: catRes.ok,
            unchanged: true,
            meta: catRes.meta,
            builtAt: catalog.builtAt
        };
    }

    const ordered = Array.from(toRefresh);
    const total = ordered.length;
    let refreshed = 0;
    let skipped = 0;
    let failed = 0;
    let index = 0;

    if (total > 0) {
        await setListApplyProgress({
            phase: 'loading',
            current: 0,
            total,
            title: `Loading lists 0 / ${total}`,
            detail: 'Preparing…'
        });
    }

    try {
        for (const listId of ordered) {
            // Re-check selection each time (queued toggles run after this refresh).
            const live = await storageGet({ threatFeeds: {}, enabledFilterLists: [] });
            const stillOn = !!(live.threatFeeds || {})[listId]
                || (live.enabledFilterLists || []).includes(listId);
            if (!stillOn) continue;

            index += 1;
            const name = listDisplayName(catalog, listId);
            await setListApplyProgress({
                phase: 'loading',
                current: index,
                total,
                listId,
                title: `Loading lists ${index} / ${total}`,
                detail: name
            });

            const res = await setRemoteListEnabledNow(listId, true, {
                catalog,
                skipIfUnchanged: !force,
                preferCache: !!force
            });
            if (res.success && res.unchanged) {
                skipped += 1;
            } else if (res.success) {
                refreshed += 1;
            } else {
                failed += 1;
            }
        }

        await storageSet({
            liveListsLastSync: new Date().toISOString(),
            remoteListsLastSync: new Date().toISOString(),
            remoteListsAppliedBuiltAt: catalog.builtAt || null
        });

        return {
            ok: failed === 0,
            refreshed,
            skipped,
            failed,
            catalogOk: catRes.ok,
            unchanged: refreshed === 0 && failed === 0,
            meta: catRes.meta,
            builtAt: catalog.builtAt
        };
    } finally {
        await clearListApplyProgress({
            phase: 'loading',
            current: index,
            total,
            refreshed,
            skipped,
            failed
        });
    }
}

async function suspendEnabledRemoteListsNow() {
    const store = await storageGet({
        threatFeeds: {},
        remoteManagedLists: {},
        enabledFilterLists: []
    });
    const ids = Array.from(new Set([
        ...Object.keys(store.threatFeeds || {}).filter((id) => store.threatFeeds[id]),
        ...Object.keys(store.remoteManagedLists || {}).filter((id) => store.remoteManagedLists[id]),
        ...(store.enabledFilterLists || [])
    ]));
    const { catalog } = await getCachedCatalog();
    const total = ids.length;
    let index = 0;

    if (total > 0) {
        await setListApplyProgress({
            phase: 'removing',
            current: 0,
            total,
            title: `Removing lists 0 / ${total}`,
            detail: 'Pausing AdBlocker…'
        });
    }

    try {
        for (const listId of ids) {
            index += 1;
            await setListApplyProgress({
                phase: 'removing',
                current: index,
                total,
                listId,
                title: `Removing lists ${index} / ${total}`,
                detail: listDisplayName(catalog, listId)
            });
            await setRemoteListEnabledNow(listId, false, { keepSelection: true, catalog });
        }
        return { success: true, suspended: ids.length };
    } finally {
        await clearListApplyProgress({
            phase: 'removing',
            current: index,
            total,
            suspended: ids.length
        });
    }
}

async function repairIncompleteRemoteListsNow() {
    const d = await storageGet({
        moduleStates: {},
        masterSwitch: true,
        enabledFilterLists: [],
        threatFeeds: {},
        remoteListRevisions: {},
        listApplyProgress: null
    });

    const progress = d.listApplyProgress;
    const wasInterrupted = !!(progress && progress.active);
    if (wasInterrupted) {
        await clearListApplyProgress({
            interrupted: true,
            phase: progress.phase || null,
            current: progress.current || 0,
            total: progress.total || 0
        });
    }

    const adOn = d.masterSwitch !== false && d.moduleStates.adBlocker !== false;
    const selected = collectSelectedListIds(d);

    // AdBlocker/master off keeps installed DNR rules in place (gated by a
    // high-priority pause allow rule in background.js). Do not unload here.
    if (!adOn) {
        return { repaired: false, reason: 'adblocker_off' };
    }

    const missing = Array.from(selected).filter((id) => !d.remoteListRevisions?.[id]);
    const rulesMissing = selected.size > 0 && !(await hasInstalledFilterListRules());
    if (missing.length === 0 && !rulesMissing && !wasInterrupted) {
        return { repaired: false, reason: 'complete' };
    }

    // Resume: reinstall missing (and re-check others). Prefer cache when recovering.
    const res = await refreshEnabledRemoteListsNow({ force: true });
    return {
        repaired: true,
        reason: wasInterrupted ? 'interrupted_load' : (rulesMissing ? 'missing_rules' : 'missing_revisions'),
        missing,
        ...res
    };
}

/** True if any remote filter-list dynamic DNR rules are currently installed. */
export async function hasInstalledFilterListRules() {
    const existing = await brw.declarativeNetRequest.getDynamicRules().catch(() => []);
    return (existing || []).some(
        (r) => r.id >= RULE_ID_FLOOR && r.id <= RULE_ID_CEILING
    );
}

/**
 * Whether turning AdBlocker on needs a list restore/download (vs instant unpause).
 */
export async function needsRemoteListRestore() {
    const d = await storageGet({
        enabledFilterLists: [],
        threatFeeds: {},
        remoteListRevisions: {},
        moduleStates: {},
        masterSwitch: true
    });
    if (d.masterSwitch === false || d.moduleStates.adBlocker === false) {
        return false;
    }
    const selected = collectSelectedListIds(d);
    if (selected.size === 0) return false;
    for (const id of selected) {
        if (!d.remoteListRevisions?.[id]) return true;
    }
    return !(await hasInstalledFilterListRules());
}

export function ensureRemoteListsAlarm() {
    if (!brw.alarms) return;
    brw.alarms.create('refreshRemoteLists', { periodInMinutes: 60 * 24 });
}

export async function getCatalogForUi() {
    const d = await storageGet({ remoteCatalogMeta: null });
    const fetchedAt = d.remoteCatalogMeta?.fetchedAt
        ? Date.parse(d.remoteCatalogMeta.fetchedAt)
        : 0;
    const stale = !fetchedAt || (Date.now() - fetchedAt > 20 * 60 * 60 * 1000);

    const cached = await getCachedCatalog();
    if (stale) {
        refreshRemoteCatalog({ force: false }).catch(() => { });
    }

    const enabled = await storageGet({
        enabledFilterLists: [],
        threatFeeds: {},
        threatCounts: {},
        liveListMeta: {},
        remoteManagedLists: {},
        remoteCatalogMeta: null,
        liveListsLastSync: null,
        remoteListsLastSync: null
    });

    const budget = await getDnrBudgetSnapshot().catch(() => null);

    return {
        catalog: cached.catalog,
        meta: enabled.remoteCatalogMeta || cached.meta,
        enabledFilterLists: enabled.enabledFilterLists || [],
        threatFeeds: enabled.threatFeeds || {},
        threatCounts: enabled.threatCounts || {},
        liveListMeta: enabled.liveListMeta || {},
        remoteManagedLists: enabled.remoteManagedLists || {},
        lastSync: enabled.remoteListsLastSync || enabled.liveListsLastSync || null,
        maxDynamicRules: MAX_DYNAMIC_RULES,
        maxRegexRules: MAX_REGEX_RULES,
        maxUnsafeDynamicRules: MAX_UNSAFE_DYNAMIC_RULES,
        budget
    };
}

/** Ids whose network rules are served as remote dynamic DNR (skip static). */
export async function getRemoteManagedListIds() {
    const d = await storageGet({ remoteManagedLists: {} });
    return Object.keys(d.remoteManagedLists || {}).filter(id => d.remoteManagedLists[id]);
}
