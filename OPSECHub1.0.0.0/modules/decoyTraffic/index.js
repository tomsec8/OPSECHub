const brw = typeof browser !== 'undefined' ? browser : chrome;

const DECOY_URLS = [
    'https://www.wikipedia.org/',
    'https://www.github.com/',
    'https://www.reddit.com/',
    'https://news.ycombinator.com/',
    'https://www.bbc.com/',
    'https://www.cnn.com/',
    'https://www.nytimes.com/',
    'https://www.amazon.com/',
    'https://www.ebay.com/',
    'https://www.apple.com/',
    'https://www.microsoft.com/',
    'https://www.netflix.com/',
    'https://www.imdb.com/',
    'https://www.stackoverflow.com/',
    'https://www.medium.com/',
    'https://www.twitch.tv/',
    'https://www.pinterest.com/',
    'https://www.quora.com/',
    'https://www.yelp.com/',
    'https://www.tripadvisor.com/',
    'https://www.booking.com/',
    'https://www.paypal.com/',
    'https://www.weather.com/',
    'https://www.espn.com/',
    'https://www.ign.com/',
    'https://www.webmd.com/',
    'https://www.healthline.com/',
    'https://www.nasa.gov/',
    'https://www.nationalgeographic.com/',
    'https://www.forbes.com/',
    'https://www.bloomberg.com/',
    'https://www.wsj.com/',
    'https://www.theguardian.com/',
    'https://www.reuters.com/',
    'https://www.etsy.com/',
    'https://www.target.com/',
    'https://www.walmart.com/',
    'https://www.bestbuy.com/',
    'https://www.homedepot.com/',
    'https://www.ikea.com/',
    'https://www.spotify.com/',
    'https://www.soundcloud.com/',
    'https://www.adobe.com/',
    'https://www.salesforce.com/'
];

const SEARCH_QUERIES = [
    'https://html.duckduckgo.com/html/?q=latest+technology+news',
    'https://html.duckduckgo.com/html/?q=best+privacy+tools',
    'https://html.duckduckgo.com/html/?q=open+source+security',
    'https://html.duckduckgo.com/html/?q=weather+forecast+today',
    'https://html.duckduckgo.com/html/?q=wikipedia+history+articles',
    'https://html.duckduckgo.com/html/?q=world+news+headlines',
    'https://html.duckduckgo.com/html/?q=space+exploration+updates'
];

async function generateDecoyRequest() {
    try {
        const data = await brw.storage.local.get({ includeSearches: true });
        let pool = [...DECOY_URLS];
        if (data.includeSearches) {
            pool = pool.concat(SEARCH_QUERIES);
        }

        const url = pool[Math.floor(Math.random() * pool.length)];
        console.log(`[OPSECHub:DecoyTraffic] Sending decoy noise request to: ${url}`);
        fetch(url, { mode: 'no-cors', cache: 'no-store' }).catch(() => {});
    } catch (e) {
        console.warn('[OPSECHub:DecoyTraffic] Failed to send request:', e);
    }
}

// MV3 Service Worker Alarm Listener - uses storage check so sleep/wake cycles don't kill alarms
brw.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'decoyTrafficAlarm') {
        const data = await brw.storage.local.get({ moduleStates: {}, masterSwitch: true });
        if (data.masterSwitch && data.moduleStates && data.moduleStates.decoyTraffic) {
            generateDecoyRequest();
        } else {
            brw.alarms.clear('decoyTrafficAlarm');
        }
    }
});

async function enable() {
    console.log('[OPSECHub] Decoy Traffic ENABLED/UPDATED');
    const data = await brw.storage.local.get({ decoyIntensity: 'medium' });
    
    let period = 0.25; // medium (approx 15 seconds)
    if (data.decoyIntensity === 'low') period = 1.0; // 60 seconds
    else if (data.decoyIntensity === 'high') period = 0.1; // 6 seconds

    await brw.alarms.clear('decoyTrafficAlarm');
    brw.alarms.create('decoyTrafficAlarm', { periodInMinutes: period });
    generateDecoyRequest();
}

async function disable() {
    console.log('[OPSECHub] Decoy Traffic DISABLED');
    await brw.alarms.clear('decoyTrafficAlarm');
}

export default {
    toggle: async (enabled) => {
        if (enabled) await enable();
        else await disable();
    }
};
