(() => {
    if (window.__webGuardOverlayLoaded) return;
    window.__webGuardOverlayLoaded = true;

    function createElement(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text !== undefined) element.textContent = text;
        return element;
    }

    function showWarning(detection) {
        if (document.getElementById("webguard-overlay")) return;

        const overlay = createElement("div");
        overlay.id = "webguard-overlay";
        const backdrop = createElement("div", "webguard-backdrop");
        const card = createElement("section", "webguard-card");
        card.setAttribute("role", "dialog");
        card.setAttribute("aria-modal", "true");
        card.setAttribute("aria-labelledby", "wg-title");

        card.append(
            createElement("div", "webguard-icon", "⚠"),
            createElement("h1", "", "Potentially Risky Website Indicators")
        );
        card.lastChild.id = "wg-title";
        card.appendChild(createElement("p", "webguard-subtitle", "WebGuard AI found indicators that may deserve your attention. This is a heuristic assessment, not proof of malicious activity."));

        const riskBox = createElement("div", "webguard-risk-box");
        const details = [
            ["Website", detection.domain || "Unknown"],
            ["Heuristic score", `${Number(detection.riskScore) || 0}/100`],
            ["Risk level", detection.riskLevel || "UNKNOWN"]
        ];
        for (const [label, value] of details) {
            const item = createElement("div");
            item.append(createElement("span", "", label), createElement("strong", "", value));
            riskBox.appendChild(item);
        }
        card.appendChild(riskBox);

        const reasonBox = createElement("div", "webguard-reasons");
        reasonBox.appendChild(createElement("h3", "", "Why was it flagged?"));
        const list = createElement("ul");
        const reasons = Array.isArray(detection.reasons) ? detection.reasons : [];
        for (const reason of reasons) list.appendChild(createElement("li", "", String(reason)));
        if (!reasons.length) list.appendChild(createElement("li", "", "No detailed indicators were provided."));
        reasonBox.appendChild(list);
        card.appendChild(reasonBox);

        const advice = createElement("div", "webguard-advice");
        advice.append(createElement("strong", "", "Recommended action"), createElement("p", "", "Avoid entering sensitive information until you have independently verified the website."));
        card.appendChild(advice);

        const buttons = createElement("div", "webguard-buttons");
        const back = createElement("button", "wg-back-button", "Go Back");
        const proceed = createElement("button", "wg-continue-button", "Continue Anyway");
        back.type = "button";
        proceed.type = "button";
        back.addEventListener("click", () => chrome.runtime.sendMessage({ type: "WEBGUARD_GO_BACK" }));
        proceed.addEventListener("click", () => {
            overlay.remove();
            chrome.runtime.sendMessage({ type: "WEBGUARD_CONTINUE" });
        });
        buttons.append(back, proceed);
        card.appendChild(buttons);
        overlay.append(backdrop, card);
        document.documentElement.appendChild(overlay);
    }

    chrome.runtime.onMessage.addListener(message => {
        if (message.type === "WEBGUARD_SHOW_WARNING" && message.detection) showWarning(message.detection);
    });
})();
