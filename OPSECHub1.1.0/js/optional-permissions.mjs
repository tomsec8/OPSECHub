/**
 * Optional permissions for non-AdBlocker tools.
 * Requested at enable-time with an explanation dialog first.
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

/** @typedef {{ permissions?: string[], origins?: string[], title: string, reason: string }} PermSpec */

/** @type {Record<string, PermSpec>} */
export const MODULE_OPTIONAL_PERMISSIONS = {
    webrtcBlock: {
        permissions: ['privacy'],
        title: 'WebRTC Leak Block',
        reason:
            'Needs Chrome’s privacy setting so WebRTC cannot expose your real IP. ' +
            'Without it, this protection cannot be applied.'
    },
    locationBlock: {
        permissions: ['contentSettings'],
        title: 'Location Guard',
        reason:
            'Needs permission to change site location access (block / ask). ' +
            'Used only to control geolocation for websites.'
    },
    mediaBlock: {
        permissions: ['contentSettings'],
        title: 'Camera & Mic Block',
        reason:
            'Needs permission to change camera and microphone site settings. ' +
            'Used only to block or restore media device access.'
    },
    // Note: chrome.proxy cannot be optional in Chrome — it stays a required
    // manifest permission. Proxy Manager therefore has no runtime grant step.
    cookieGuard: {
        permissions: ['browsingData'],
        title: 'Cookie & Storage Guard',
        reason:
            'Needs permission to delete cookies and site storage when you close the last tab for a site.'
    }
};

/** One-shot tools / actions (not module toggles). */
export const FEATURE_OPTIONAL_PERMISSIONS = {
    browsingDataTools: {
        permissions: ['browsingData'],
        title: 'Clear browsing data',
        reason:
            'Needs permission to clear history, cache, cookies, or site data when you use a wipe action.'
    },
    linkTracer: {
        permissions: ['webRequest'],
        title: 'Short Link Tracer',
        reason:
            'Needs permission to observe redirects while tracing a short link, so hops can be listed accurately.'
    }
};

function normalizeSpec(spec) {
    return {
        permissions: [...(spec.permissions || [])],
        origins: [...(spec.origins || [])]
    };
}

export function getModulePermSpec(moduleId) {
    return MODULE_OPTIONAL_PERMISSIONS[moduleId] || null;
}

export function getFeaturePermSpec(featureId) {
    return FEATURE_OPTIONAL_PERMISSIONS[featureId] || null;
}

export async function permissionsGranted(spec) {
    if (!spec) return true;
    const want = normalizeSpec(spec);
    if (!want.permissions.length && !want.origins.length) return true;
    try {
        return await brw.permissions.contains(want);
    } catch {
        return false;
    }
}

export async function hasModuleOptionalPermissions(moduleId) {
    const spec = getModulePermSpec(moduleId);
    if (!spec) return true;
    return permissionsGranted(spec);
}

export async function requestPermissions(spec) {
    if (!spec) return true;
    const want = normalizeSpec(spec);
    if (!want.permissions.length && !want.origins.length) return true;
    try {
        return await brw.permissions.request(want);
    } catch (err) {
        console.warn('[OPSECHub] permissions.request failed:', err);
        return false;
    }
}

/**
 * Pre-prompt explaining why, then Chrome’s permission dialog.
 * Chrome requires permissions.request() inside a user-gesture handler, so the
 * actual request runs from the dialog’s Continue button click.
 * @returns {Promise<{ granted: boolean, cancelled?: boolean, denied?: boolean }>}
 */
export async function explainAndRequest(spec, { explainFn } = {}) {
    if (!spec) return { granted: true };
    if (await permissionsGranted(spec)) return { granted: true };

    if (explainFn) {
        const accepted = await explainFn(spec);
        if (!accepted) return { granted: false, cancelled: true };
        const granted = await requestPermissions(spec);
        return granted ? { granted: true } : { granted: false, denied: true };
    }

    return explainThenRequestDialog(spec);
}

export async function ensureModulePermissions(moduleId, opts = {}) {
    const spec = getModulePermSpec(moduleId);
    if (!spec) return { granted: true };
    return explainAndRequest(spec, opts);
}

export async function ensureFeaturePermissions(featureId, opts = {}) {
    const spec = getFeaturePermSpec(featureId);
    if (!spec) return { granted: true };
    return explainAndRequest(spec, opts);
}

/** Modules that should auto-disable if the user revokes optional perms. */
export function modulesNeedingPermission(permission) {
    const hit = [];
    for (const [id, spec] of Object.entries(MODULE_OPTIONAL_PERMISSIONS)) {
        if ((spec.permissions || []).includes(permission)) hit.push(id);
    }
    return hit;
}

function explainThenRequestDialog(spec) {
    return new Promise((resolve) => {
        const existing = document.getElementById('opsec-perm-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'opsec-perm-modal';
        overlay.className = 'opsec-perm-overlay';
        overlay.innerHTML = `
            <div class="opsec-perm-dialog" role="dialog" aria-modal="true" aria-labelledby="opsec-perm-title">
                <h3 id="opsec-perm-title">Allow “${escapeHtml(spec.title)}”?</h3>
                <p class="opsec-perm-reason">${escapeHtml(spec.reason)}</p>
                <p class="opsec-perm-note">Chrome will show a short confirmation next. If you decline, this tool stays off — you can turn it on again anytime.</p>
                <div class="opsec-perm-actions">
                    <button type="button" class="opsec-perm-btn secondary" data-act="cancel">Not now</button>
                    <button type="button" class="opsec-perm-btn primary" data-act="allow">Continue</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const close = () => overlay.remove();

        overlay.querySelector('[data-act="cancel"]').addEventListener('click', () => {
            close();
            resolve({ granted: false, cancelled: true });
        });
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                close();
                resolve({ granted: false, cancelled: true });
            }
        });
        // Must call permissions.request from this click to keep the user gesture.
        overlay.querySelector('[data-act="allow"]').addEventListener('click', () => {
            const want = normalizeSpec(spec);
            Promise.resolve(brw.permissions.request(want))
                .then((granted) => {
                    close();
                    resolve(granted ? { granted: true } : { granted: false, denied: true });
                })
                .catch((err) => {
                    console.warn('[OPSECHub] permissions.request failed:', err);
                    close();
                    resolve({ granted: false, denied: true });
                });
        });
    });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/** Brief status toast (popup / options). */
export function showPermToast(message, { isError = false } = {}) {
    if (typeof document === 'undefined') return;
    let el = document.getElementById('opsec-perm-toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'opsec-perm-toast';
        el.className = 'opsec-perm-toast';
        document.body.appendChild(el);
    }
    el.textContent = message;
    el.classList.toggle('is-error', !!isError);
    el.classList.add('show');
    clearTimeout(showPermToast._t);
    showPermToast._t = setTimeout(() => el.classList.remove('show'), 3200);
}
