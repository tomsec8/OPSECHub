/*******************************************************************************

    Cosmetic filtering and scriptlet injection.

    declarativeNetRequest can only block or redirect a request. A large part of
    what filter lists do is neither: hiding elements that were served inline,
    and neutering ad logic from inside the page. YouTube's video ads, for one,
    are removed entirely by scriptlets that prune `adPlacements` out of the
    player response -- no network rule can express that.

    tools/build-rules.mjs turns those filters into content scripts, one set per
    filter list. This module registers the sets belonging to the lists the user
    has enabled, mirroring uBlock Origin Lite's scripting-manager.js.

*/

const brw = globalThis.browser ?? globalThis.chrome;

const DETAILS_URL = 'rules/scripting/details.json';
// Privacy modules register content scripts of their own through the same API,
// so every id this module owns carries a prefix and only those are torn down.
const ID_PREFIX = 'cosmetic.';
const CSS_API = '/js/scripting/css-api.js';
const ISOLATED_API = '/js/scripting/isolated-api.js';
const PROCEDURAL_API = '/js/scripting/css-procedural-api.js';

let detailsPromise;

function getDetails() {
    if ( detailsPromise === undefined ) {
        detailsPromise = fetch(brw.runtime.getURL(DETAILS_URL))
            .then(r => (r.ok ? r.json() : []))
            .then(entries => new Map(entries))
            .catch(() => new Map());
    }
    return detailsPromise;
}

/** Merge remote scriptlet host maps (from Git) onto bundled details.json. */
async function getDetailsMerged() {
    const base = await getDetails();
    const map = new Map(base);
    try {
        const d = await brw.storage.local.get({ remoteScriptletMeta: {} });
        for (const [id, meta] of Object.entries(d.remoteScriptletMeta || {})) {
            if (!meta) continue;
            const prev = map.get(id) || {};
            const next = { ...prev };
            if (meta.hosts) next.scriptlet = meta.hosts;
            if (meta.hasScriptlets && !next.scriptlet) {
                next.scriptlet = prev.scriptlet || { MAIN: ['*'] };
            }
            map.set(id, next);
        }
    } catch { /* ignore */ }
    return map;
}

const matchFromHostname = hn =>
    hn === '*' || hn === 'all-urls' ? '<all_urls>' : `*://*.${hn}/*`;

// A single '<all_urls>' entry subsumes every other pattern, and Chrome is
// noticeably faster to register one pattern than tens of thousands.
function matchesFromHostnames(hostnames) {
    const out = [];
    for ( const hn of hostnames ) {
        const match = matchFromHostname(hn);
        if ( match === '<all_urls>' ) { return [ '<all_urls>' ]; }
        out.push(match);
    }
    return out;
}

/******************************************************************************/

function addScriptletDirectives(out, enabledIds, details, excludeMatches) {
    for ( const id of enabledIds ) {
        const worlds = details.get(id)?.scriptlet;
        if ( worlds === undefined ) { continue; }
        for ( const [ world, hostnames ] of Object.entries(worlds) ) {
            const matches = matchesFromHostnames(hostnames);
            if ( matches.length === 0 ) { continue; }
            const directive = {
                id: `${ID_PREFIX}${id}.${world.toLowerCase()}`,
                js: [ `/rules/scripting/scriptlet/${world.toLowerCase()}/${id}.js` ],
                matches,
                allFrames: true,
                matchOriginAsFallback: true,
                runAt: 'document_start',
                world,
            };
            if ( excludeMatches.length !== 0 ) {
                directive.excludeMatches = excludeMatches;
            }
            out.push(directive);
        }
    }
}

async function addSpecificCosmeticDirective(out, enabledIds, details, excludeMatches) {
    // Prefer lists that either have bundled specific data OR remote cosmetics cached.
    const usable = [];
    for (const id of enabledIds) {
        if (details.get(id)?.specific) {
            usable.push(id);
            continue;
        }
        const probe = await brw.storage.local.get([`remoteCosmetic.${id}`, `css.specific.${id}`]);
        if (probe[`remoteCosmetic.${id}`] || probe[`css.specific.${id}`]) usable.push(id);
    }
    if (usable.length === 0) { return; }

    // css-specific.js looks its selectors up by hostname at document_start, so
    // the tables have to be in storage before the first navigation, not
    // fetched from inside the content script.
    const payload = {};
    await Promise.all(usable.map(async id => {
        const keys = await brw.storage.local.get([
            `remoteCosmetic.${id}`,
            `css.specific.${id}`
        ]);
        if (keys[`remoteCosmetic.${id}`]) {
            payload[`css.specific.${id}`] = keys[`remoteCosmetic.${id}`];
            return;
        }
        if (keys[`css.specific.${id}`]) {
            payload[`css.specific.${id}`] = keys[`css.specific.${id}`];
            return;
        }
        try {
            const data = await fetch(brw.runtime.getURL(`rules/scripting/specific/${id}.json`))
                .then(r => (r.ok ? r.json() : undefined));
            if (data) payload[`css.specific.${id}`] = data;
        } catch { /* ignore */ }
    }));
    if (Object.keys(payload).length !== 0) {
        await brw.storage.local.set(payload);
    }

    const idsWithData = usable.filter(id => payload[`css.specific.${id}`] || details.get(id)?.specific);
    if (idsWithData.length === 0) { return; }

    const directive = {
        id: `${ID_PREFIX}css-specific`,
        js: [
            CSS_API,
            ISOLATED_API,
            ...idsWithData.map(id => `/rules/scripting/specific/${id}.js`),
            '/js/scripting/css-specific.js',
        ],
        matches: [ '<all_urls>' ],
        allFrames: true,
        runAt: 'document_start',
    };
    if ( excludeMatches.length !== 0 ) {
        directive.excludeMatches = excludeMatches;
    }
    out.push(directive);
}

function addGenericCosmeticDirective(out, enabledIds, details, excludeMatches) {
    const ids = enabledIds.filter(id => details.get(id)?.generic);
    if ( ids.length === 0 ) { return; }

    // `#@#` generic exceptions and `$generichide` name the sites where the
    // generic sweep does more harm than good.
    const unhide = [];
    for ( const id of enabledIds ) {
        const hostnames = details.get(id)?.generichide?.unhide;
        if ( hostnames ) { unhide.push(...hostnames); }
    }

    const directive = {
        id: `${ID_PREFIX}css-generic`,
        js: [
            CSS_API,
            ISOLATED_API,
            ...ids.map(id => `/rules/scripting/generic/${id}.js`),
            '/js/scripting/css-generic.js',
        ],
        matches: [ '<all_urls>' ],
        allFrames: true,
        runAt: 'document_idle',
    };
    const excluded = [
        ...excludeMatches,
        ...matchesFromHostnames(unhide).filter(m => m !== '<all_urls>'),
    ];
    if ( excluded.length !== 0 ) { directive.excludeMatches = excluded; }
    out.push(directive);
}

/******************************************************************************/

// Serialized for the same reason the DNR sync is: overlapping runs would
// unregister each other's scripts halfway through.
let queue = Promise.resolve();

export function syncContentScripts(enabledIds, options) {
    const run = () => syncNow(enabledIds, options);
    const next = queue.then(run, run);
    queue = next.catch(() => { });
    return next;
}

async function syncNow(enabledIds, { enabled = true, excludedDomains = [], generic = true } = {}) {
    if ( brw.scripting?.registerContentScripts === undefined ) { return; }

    const excludeMatches = excludedDomains
        .map(matchFromHostname)
        .filter(m => m !== '<all_urls>');

    // css-specific.js reads this to bail out on excluded sites even when a
    // frame slipped past excludeMatches.
    await brw.storage.local.set({
        filteringModeDetails: { none: excludedDomains },
    });

    const toAdd = [];
    if ( enabled ) {
        const details = await getDetailsMerged();
        addScriptletDirectives(toAdd, enabledIds, details, excludeMatches);
        await addSpecificCosmeticDirective(toAdd, enabledIds, details, excludeMatches);
        if ( generic ) {
            addGenericCosmeticDirective(toAdd, enabledIds, details, excludeMatches);
        }
    }

    const stale = await brw.scripting.getRegisteredContentScripts()
        .then(scripts => scripts
            .map(s => s.id)
            .filter(id => id.startsWith(ID_PREFIX)))
        .catch(() => []);
    if ( stale.length !== 0 ) {
        await brw.scripting.unregisterContentScripts({ ids: stale })
            .catch(err => console.error('[OPSECHub] Failed to unregister cosmetic scripts:', err));
    }

    if ( toAdd.length === 0 ) {
        console.log('[OPSECHub] Cosmetic filtering: no content scripts registered.');
        return;
    }

    try {
        await brw.scripting.registerContentScripts(toAdd);
        console.log(`[OPSECHub] Cosmetic filtering: registered ${toAdd.length} content scripts.`);
    } catch ( err ) {
        // One bad directive rejects the whole batch, so fall back to
        // registering them one at a time rather than losing every script.
        console.error('[OPSECHub] Bulk content script registration failed:', err);
        for ( const directive of toAdd ) {
            await brw.scripting.registerContentScripts([ directive ])
                .catch(e => console.error(`[OPSECHub] Skipping "${directive.id}":`, e));
        }
    }
}

/******************************************************************************/

// The cosmetic engine asks the service worker to do the things a content
// script cannot: apply a user stylesheet, and pull in the procedural
// filterer on the rare pages that need it.
export function handleScriptingMessage(message, sender, sendResponse) {
    const { what } = message;
    if ( what !== 'insertCSS' && what !== 'removeCSS' && what !== 'injectCSSProceduralAPI' ) {
        return false;
    }

    const tabId = sender.tab?.id;
    if ( tabId === undefined ) { return false; }
    const target = { tabId, frameIds: [ sender.frameId ?? 0 ] };

    if ( what === 'injectCSSProceduralAPI' ) {
        brw.scripting.executeScript({ target, files: [ PROCEDURAL_API ] })
            .then(() => sendResponse(true))
            .catch(() => sendResponse(false));
        return true;
    }

    const details = { target, css: message.css, origin: 'USER' };
    const op = what === 'insertCSS'
        ? brw.scripting.insertCSS(details)
        : brw.scripting.removeCSS(details);
    op.then(() => sendResponse(true)).catch(() => sendResponse(false));
    return true;
}
