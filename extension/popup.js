/**
 * AegisShield Extension Popup Controller (v2.6)
 */

let currentTabId = null;
let currentResult = null;
let currentHostname = "";

function applyVerdictTheme(score, classification) {
  const verdictEl = document.getElementById("tab-verdict");
  const scoreEl = document.getElementById("tab-score");
  verdictEl.textContent = classification || "Low Risk";
  scoreEl.textContent = `${score ?? 0}/100`;

  if (score >= 60 || classification === "Confirmed Malicious" || classification === "High Risk") {
    verdictEl.style.background = "rgba(239, 68, 68, 0.2)";
    verdictEl.style.color = "#fca5a5";
    verdictEl.style.border = "1px solid #ef4444";
    scoreEl.style.color = "#fca5a5";
  } else if (score >= 25 || classification === "Suspicious") {
    verdictEl.style.background = "rgba(245, 158, 11, 0.2)";
    verdictEl.style.color = "#fcd34d";
    verdictEl.style.border = "1px solid #f59e0b";
    scoreEl.style.color = "#fcd34d";
  } else {
    verdictEl.style.background = "rgba(16, 185, 129, 0.2)";
    verdictEl.style.color = "#6ee7b7";
    verdictEl.style.border = "1px solid #10b981";
    scoreEl.style.color = "#6ee7b7";
  }
}

function updateWhitelistButton(isWhitelisted) {
  const btn = document.getElementById("btn-whitelist");
  if (!btn) return;
  if (isWhitelisted) {
    btn.textContent = "⭐ Domain Trusted (In Whitelist)";
    btn.classList.add("active");
  } else {
    btn.textContent = "⭐ Trust Domain (Add to Whitelist)";
    btn.classList.remove("active");
  }
}

function checkWhitelistStatus(hostname) {
  if (!hostname) return;
  chrome.storage.local.get(["user_whitelist"], (res) => {
    const list = res.user_whitelist || [];
    const isW = list.includes(hostname.toLowerCase());
    updateWhitelistButton(isW);
    if (isW) {
      document.getElementById("tab-verdict").textContent = "Trusted (Whitelisted)";
      document.getElementById("tab-verdict").style.background = "rgba(16, 185, 129, 0.2)";
      document.getElementById("tab-verdict").style.color = "#6ee7b7";
      document.getElementById("tab-score").textContent = "0/100";
    }
  });
}

function renderResult(result) {
  if (!result) return;
  currentResult = result;
  document.getElementById("tab-url").textContent = result.primary_target || "Target";
  applyVerdictTheme(result.risk_score, result.risk_classification);
  document.getElementById("tab-reply").textContent = result.copilot_reply || "";

  const list = document.getElementById("tab-findings");
  const findings = result.findings || [];
  if (findings.length === 0) {
    list.innerHTML = `<li>No deceptive lexical, TLS/CA, or campaign cluster indicators triggered. (Note: Never labeled 'Safe'—lowest tier is Low Risk.)</li>`;
  } else {
    list.innerHTML = findings
      .slice(0, 4)
      .map((f) => `<li><strong>[${f.severity}] ${f.title}:</strong> ${f.evidence}</li>`)
      .join("");
  }
}

function triggerScan(queryStr) {
  document.getElementById("tab-verdict").textContent = "Agent Thinking...";
  chrome.runtime.sendMessage(
    {
      type: "AEGIS_MANUAL_INVESTIGATE",
      tabId: currentTabId,
      payload: {
        query: queryStr,
        page_url: queryStr.startsWith("http") ? queryStr : null,
        has_password_form: false,
        auto_anchor_web3: true
      }
    },
    (response) => {
      if (response && response.ok && response.result) {
        renderResult(response.result);
      } else {
        document.getElementById("api-status").textContent = "API OFFLINE";
        document.getElementById("api-status").style.color = "#fca5a5";
        document.getElementById("tab-reply").textContent =
          "Start the AegisTrust FastAPI server on http://localhost:8000 to enable live AI Agent telemetry.";
      }
    }
  );
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];
    if (!activeTab) return;
    currentTabId = activeTab.id;
    const url = activeTab.url || "";
    document.getElementById("tab-url").textContent = url;

    try {
      const u = new URL(url);
      currentHostname = u.hostname;
      checkWhitelistStatus(currentHostname);
    } catch (_) {
      currentHostname = "";
    }

    chrome.storage.local.get([`tab_${currentTabId}`], (stored) => {
      if (stored && stored[`tab_${currentTabId}`]) {
        renderResult(stored[`tab_${currentTabId}`]);
      } else if (url.startsWith("http")) {
        triggerScan(url);
      } else {
        document.getElementById("tab-verdict").textContent = "Browser Internal Page";
        document.getElementById("tab-score").textContent = "0/100";
      }
    });
  });

  document.getElementById("btn-whitelist").addEventListener("click", () => {
    if (!currentHostname) return;
    chrome.storage.local.get(["user_whitelist"], (res) => {
      let list = res.user_whitelist || [];
      const lower = currentHostname.toLowerCase();
      if (list.includes(lower)) {
        list = list.filter((h) => h !== lower);
        updateWhitelistButton(false);
        if (currentResult) renderResult(currentResult);
      } else {
        list.push(lower);
        updateWhitelistButton(true);
        document.getElementById("tab-verdict").textContent = "Trusted (Whitelisted)";
        document.getElementById("tab-verdict").style.background = "rgba(16, 185, 129, 0.2)";
        document.getElementById("tab-verdict").style.color = "#6ee7b7";
        document.getElementById("tab-score").textContent = "0/100";
        if (currentTabId) {
          chrome.action.setBadgeText({ tabId: currentTabId, text: "OK" });
          chrome.action.setBadgeBackgroundColor({ tabId: currentTabId, color: "#10b981" });
        }
      }
      chrome.storage.local.set({ user_whitelist: list });
    });
  });

  document.getElementById("btn-ask").addEventListener("click", () => {
    const q = document.getElementById("quick-query").value.trim();
    if (q) triggerScan(q);
  });

  document.getElementById("btn-simulate-block").addEventListener("click", () => {
    if (!currentTabId) return;
    const demoData = currentResult && currentResult.risk_score >= 60 ? currentResult : {
      primary_target: "xn--pypal-4ve.com (Simulated Phishing Attack)",
      risk_score: 92,
      risk_classification: "Confirmed Malicious",
      steps: [{}, {}, {}, {}, {}, {}, {}],
      report_hash_keccak256: "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      findings: [
        {
          severity: "CRITICAL",
          title: "IDN Homograph / Punycode Spoofing Detected",
          evidence: "Domain uses Punycode (xn--pypal-4ve.com) to visually impersonate PayPal."
        },
        {
          severity: "HIGH",
          title: "Active Credential Harvesting Form (<input type='password'>)",
          evidence: "Browser DOM sensor detected an active password login form on an untrusted lookalike domain."
        },
        {
          severity: "HIGH",
          title: "Correlated Multi-Domain Fraud Cluster",
          evidence: "Shares infrastructure in NetworkX graph with known credential-phishing campaign."
        }
      ]
    };

    chrome.tabs.sendMessage(currentTabId, {
      type: "AEGIS_BLOCK_PAGE",
      data: demoData
    });
    window.close();
  });
});
