"use strict";

const TELEMETRY_MAX_EVENTS = 1500;
const TELEMETRY_MAX_AGE_MS = 10 * 60 * 1000;
const FEATURE_WINDOW_MS = 60 * 1000;
let telemetryWriteQueue = Promise.resolve();

async function getTelemetry() {
    const result = await chrome.storage.local.get({ telemetry: [] });
    return Array.isArray(result.telemetry) ? result.telemetry : [];
}

function storeEvent(event) {
    const write = async () => {
        const now = Date.now();
        const telemetry = await getTelemetry();
        telemetry.push(event);
        const recent = telemetry.filter(item =>
            Number.isFinite(item.timestamp) && now - item.timestamp <= TELEMETRY_MAX_AGE_MS
        );
        if (recent.length > TELEMETRY_MAX_EVENTS) {
            recent.splice(0, recent.length - TELEMETRY_MAX_EVENTS);
        }
        await chrome.storage.local.set({ telemetry: recent });
    };
    // Serialize storage read/modify/write operations so simultaneous requests do not overwrite each other.
    telemetryWriteQueue = telemetryWriteQueue.then(write, write);
    return telemetryWriteQueue;
}

function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "unknown";
    }
}

async function calculateSiteFeatures(tabId, domain) {
    await telemetryWriteQueue;
    const telemetry = await getTelemetry();
    const now = Date.now();
    const tabEvents = telemetry.filter(event =>
        event.tabId === tabId && Number.isFinite(event.timestamp) &&
        now - event.timestamp <= FEATURE_WINDOW_MS
    );

    const latestNavigationEvent = tabEvents
        .filter(event => event.type === "navigation")
        .sort((left, right) => right.timestamp - left.timestamp)[0];
    const latestNavigation = latestNavigationEvent ? latestNavigationEvent.timestamp : 0;
    const assessedDomain = latestNavigationEvent?.domain || domain;

    const siteEvents = tabEvents.filter(event =>
        !latestNavigation || event.timestamp >= latestNavigation
    );
    const requests = siteEvents.filter(event => event.type === "network_request");
    const navigations = siteEvents.filter(event => event.type === "navigation");
    const uniqueDomains = new Set(requests.map(event => event.domain).filter(Boolean));
    const thirdPartyRequests = requests.filter(event =>
        event.domain && event.domain !== domain && event.domain !== "unknown"
    ).length;

    const timestamps = requests.map(event => event.timestamp);
    const elapsedSeconds = timestamps.length > 1
        ? Math.max((Math.max(...timestamps) - Math.min(...timestamps)) / 1000, 1)
        : 1;
    const requestBurstRate = Number((requests.length / elapsedSeconds).toFixed(2));
    const thirdPartyRatio = requests.length
        ? Number((thirdPartyRequests / requests.length).toFixed(3))
        : 0;

    return {
        timestamp: now,
        tab_id: tabId,
        domain: assessedDomain,
        window_seconds: FEATURE_WINDOW_MS / 1000,
        total_requests: requests.length,
        navigation_count: navigations.length,
        unique_domains: uniqueDomains.size,
        third_party_requests: thirdPartyRequests,
        third_party_ratio: thirdPartyRatio,
        request_burst_rate: requestBurstRate
    };
}

function analyzeWebsite(domain, features) {
    let riskScore = 0;
    const reasons = [];
    const host = String(domain || "unknown").toLowerCase();

    // These are weak indicators only; none proves that a website is malicious.
    const suspiciousTerms = /(?:^|[.-])(login|verify|secure|account|update|confirm|signin|banking|wallet|password|support|security)(?:[.-]|$)/i;
    if (suspiciousTerms.test(host)) {
        riskScore += 10;
        reasons.push("The hostname contains a security-sensitive term; legitimate sites may also use these terms.");
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
        riskScore += 15;
        reasons.push("The hostname contains an internationalized/punycode label that merits inspection.");
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        riskScore += 10;
        reasons.push("The website is addressed by an IPv4 literal rather than a conventional hostname.");
    }

    const subdomainCount = host === "unknown" ? 0 : Math.max(host.split(".").length - 2, 0);
    if (subdomainCount >= 4) {
        riskScore += 10;
        reasons.push("The hostname has a deep subdomain structure.");
    }
    if (features.total_requests >= 50 && features.request_burst_rate >= 10) {
        riskScore += 20;
        reasons.push("The tab generated a high request rate during the rolling observation window.");
    }
    if (features.total_requests >= 50 && features.unique_domains >= 20) {
        riskScore += 15;
        reasons.push("The tab contacted many distinct domains during the observation window.");
    }
    if (features.total_requests >= 50 && features.third_party_ratio >= 0.9 && features.unique_domains >= 20) {
        riskScore += 10;
        reasons.push("A high proportion of requests went to third-party domains.");
    }

    riskScore = Math.min(riskScore, 100);
    const riskLevel = riskScore >= 60 ? "HIGH" : (riskScore >= 30 ? "MEDIUM" : "LOW");
    return {
        domain: host,
        riskScore,
        riskLevel,
        reasons,
        assessmentType: "heuristic",
        disclaimer: "Indicators are not proof of malicious activity.",
        timestamp: Date.now()
    };
}

async function runDetection(tabId, domain) {
    const features = await calculateSiteFeatures(tabId, domain);
    const detection = analyzeWebsite(domain, features);
    await chrome.storage.local.set({ features, detection });
    return detection;
}

async function showWarning(tabId, detection) {
    const state = await chrome.storage.local.get({ warningTabs: [], warningBypassTabs: [] });
    if (state.warningTabs.includes(tabId) || state.warningBypassTabs.includes(tabId)) return;

    const warningTabs = [...state.warningTabs, tabId];
    await chrome.storage.local.set({ warningTabs });
    try {
        await chrome.tabs.sendMessage(tabId, { type: "WEBGUARD_SHOW_WARNING", detection });
    } catch {
        await chrome.storage.local.set({ warningTabs: warningTabs.filter(id => id !== tabId) });
    }
}

chrome.webNavigation.onCompleted.addListener(async details => {
    if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
    const domain = getDomain(details.url);
    const state = await chrome.storage.local.get({ warningTabs: [], warningBypassTabs: [] });
    await chrome.storage.local.set({
        warningTabs: state.warningTabs.filter(id => id !== details.tabId),
        warningBypassTabs: state.warningBypassTabs.filter(id => id !== details.tabId)
    });
    await storeEvent({ timestamp: Date.now(), type: "navigation", domain, url: details.url, tabId: details.tabId });

    // Allow the page to generate requests before calculating its first assessment.
    setTimeout(async () => {
        try {
            const detection = await runDetection(details.tabId, domain);
            if (detection.riskLevel === "HIGH") await showWarning(details.tabId, detection);
        } catch (error) {
            console.warn("WebGuard assessment failed:", error);
        }
    }, 5000);
});

chrome.webRequest.onCompleted.addListener(async details => {
    if (details.tabId < 0 || !/^https?:/i.test(details.url)) return;
    const domain = getDomain(details.url);
    await storeEvent({
        timestamp: Date.now(),
        type: "network_request",
        domain,
        method: details.method,
        resourceType: details.type,
        tabId: details.tabId
    });

    // Recalculate periodically rather than on every single request.
    if (details.type !== "main_frame") {
        const features = await calculateSiteFeatures(details.tabId, domain);
        if (features.total_requests > 0 && features.total_requests % 10 === 0) {
            const detection = analyzeWebsite(features.domain, features);
            await chrome.storage.local.set({ features, detection });
            if (detection.riskLevel === "HIGH") await showWarning(details.tabId, detection);
        }
    }
}, { urls: ["<all_urls>"] });

chrome.tabs.onRemoved.addListener(async tabId => {
    const telemetry = await getTelemetry();
    const state = await chrome.storage.local.get({ warningTabs: [], warningBypassTabs: [] });
    await chrome.storage.local.set({
        telemetry: telemetry.filter(event => event.tabId !== tabId),
        warningTabs: state.warningTabs.filter(id => id !== tabId),
        warningBypassTabs: state.warningBypassTabs.filter(id => id !== tabId)
    });
});

chrome.runtime.onMessage.addListener((message, sender) => {
    if (!sender.tab || !Number.isInteger(sender.tab.id)) return;
    const tabId = sender.tab.id;
    if (message.type === "WEBGUARD_CONTINUE") {
        chrome.storage.local.get({ warningTabs: [], warningBypassTabs: [] }).then(state =>
            chrome.storage.local.set({
                warningTabs: state.warningTabs.filter(id => id !== tabId),
                warningBypassTabs: [...state.warningBypassTabs.filter(id => id !== tabId), tabId]
            })
        );
    } else if (message.type === "WEBGUARD_GO_BACK") {
        chrome.storage.local.get({ warningTabs: [], warningBypassTabs: [] }).then(async state => {
            await chrome.storage.local.set({
                warningTabs: state.warningTabs.filter(id => id !== tabId),
                warningBypassTabs: state.warningBypassTabs.filter(id => id !== tabId)
            });
            try { await chrome.tabs.goBack(tabId); }
            catch (error) { console.warn("Could not navigate back:", error); }
        });
    }
});
