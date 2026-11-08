/**
 * AegisShield Manifest V3 Background Service Worker (v2.6)
 * - Automatically inspects navigated tabs via the Aegis Autonomous Agent API
 * - Checks User Whitelist and 24-hour Temporary Bypass Tokens
 * - Updates toolbar badge score & color
 * - Triggers full-screen phishing interception overlay on High Risk / Confirmed Malicious domains
 * - Provides Right-Click Context Menu investigation for links and selected messages
 */

const AEGIS_API_BASE = "http://localhost:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "aegis-investigate-link",
    title: "🛡️ Investigate Link with Aegis AI Agent",
    contexts: ["link"]
  });

  chrome.contextMenus.create({
    id: "aegis-investigate-selection",
    title: "🛡️ Scan Selected Message with Aegis AI Agent",
    contexts: ["selection"]
  });
});

function updateBadge(tabId, score, classification) {
  let color = "#10b981"; // Low Risk (Emerald)
  if (classification === "Confirmed Malicious" || classification === "High Risk" || score >= 60) {
    color = "#ef4444"; // Red
  } else if (classification === "Suspicious" || score >= 25) {
    color = "#f59e0b"; // Amber
  }
  chrome.action.setBadgeText({ tabId, text: String(score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function isDomainWhitelistedOrBypassed(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();
  const data = await chrome.storage.local.get(["user_whitelist", "active_bypasses"]);
  const whitelist = data.user_whitelist || [];
  if (whitelist.includes(lower)) return true;

  const bypasses = data.active_bypasses || {};
  if (bypasses[lower] && bypasses[lower] > Date.now()) return true;

  return false;
}

async function runAgentScan(payload) {
  const res = await fetch(`${AEGIS_API_BASE}/api/v1/agent/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error(`Aegis API returned ${res.status}`);
  }
  return await res.json();
}

// Listen for automatic tab navigation completion
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  if (
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("edge://") ||
    tab.url.startsWith("about:") ||
    tab.url.startsWith("chrome-extension://") ||
    tab.url.startsWith("http://localhost:8000") ||
    tab.url.startsWith("http://127.0.0.1:8000")
  ) {
    return;
  }

  try {
    const parsed = new URL(tab.url);
    if (await isDomainWhitelistedOrBypassed(parsed.hostname)) {
      chrome.action.setBadgeText({ tabId, text: "OK" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
      return;
    }

    const result = await runAgentScan({
      query: tab.url,
      page_url: tab.url,
      has_password_form: false,
      auto_anchor_web3: true
    });

    await chrome.storage.local.set({ [`tab_${tabId}`]: result, latest_scan: result });
    updateBadge(tabId, result.risk_score, result.risk_classification);

    if (result.risk_score >= 60) {
      chrome.tabs.sendMessage(tabId, {
        type: "AEGIS_BLOCK_PAGE",
        data: result
      }).catch(() => {});
    }
  } catch (err) {
    // Backend may be offline
    chrome.action.setBadgeText({ tabId, text: "OFF" });
  }
});

// Listen for DOM Password Form sensor, bypass registrations, or manual scan requests
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "AEGIS_SET_BYPASS" && msg.domain) {
    const domain = msg.domain.toLowerCase();
    chrome.storage.local.get(["active_bypasses"], (res) => {
      const bypasses = res.active_bypasses || {};
      bypasses[domain] = Date.now() + 24 * 3600 * 1000; // 24-hour bypass token
      chrome.storage.local.set({ active_bypasses: bypasses });
    });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "AEGIS_DOM_PASSWORD_DETECTED" && sender.tab) {
    const tabId = sender.tab.id;
    try {
      const parsed = new URL(msg.url);
      isDomainWhitelistedOrBypassed(parsed.hostname).then((bypassed) => {
        if (bypassed) return;
        runAgentScan({
          query: msg.url,
          page_url: msg.url,
          has_password_form: true,
          auto_anchor_web3: true
        })
          .then((result) => {
            chrome.storage.local.set({ [`tab_${tabId}`]: result, latest_scan: result });
            updateBadge(tabId, result.risk_score, result.risk_classification);
            if (result.risk_score >= 60) {
              chrome.tabs.sendMessage(tabId, { type: "AEGIS_BLOCK_PAGE", data: result }).catch(() => {});
            }
            sendResponse({ ok: true, result });
          })
          .catch((err) => sendResponse({ ok: false, error: err.message }));
      });
    } catch (_) {}
    return true;
  }

  if (msg.type === "AEGIS_MANUAL_INVESTIGATE") {
    runAgentScan(msg.payload)
      .then((result) => {
        if (msg.tabId) {
          chrome.storage.local.set({ [`tab_${msg.tabId}`]: result, latest_scan: result });
          updateBadge(msg.tabId, result.risk_score, result.risk_classification);
        }
        sendResponse({ ok: true, result });
      })
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

// Context Menu Handler
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id) return;
  const queryText = info.menuItemId === "aegis-investigate-link" ? info.linkUrl : info.selectionText;
  if (!queryText) return;

  try {
    const result = await runAgentScan({
      query: queryText,
      has_password_form: false,
      auto_anchor_web3: true
    });
    chrome.tabs.sendMessage(tab.id, {
      type: "AEGIS_SHOW_MINICARD",
      data: result
    }).catch(() => {});
  } catch (err) {
    console.warn("Aegis context menu scan failed:", err);
  }
});
