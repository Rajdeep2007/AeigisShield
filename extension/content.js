/**
 * AegisShield Content Script
 * - Inspects DOM for active credential-harvesting forms (<input type="password">)
 * - Renders the Full-Screen Red Phishing Blocker Overlay when risk_score >= 60
 * - Renders the Floating Aegis Agent Mini-Card for right-click link/message investigations
 */

(function () {
  // 1. Check for password inputs on non-local pages
  function scanDomForPasswordForms() {
    if (
      location.hostname === "localhost" ||
      location.hostname === "127.0.0.1"
    ) {
      return;
    }
    const pwdInputs = document.querySelectorAll('input[type="password"]');
    if (pwdInputs.length > 0) {
      chrome.runtime.sendMessage({
        type: "AEGIS_DOM_PASSWORD_DETECTED",
        url: window.location.href
      }).catch(() => {});
    }
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    scanDomForPasswordForms();
  } else {
    window.addEventListener("DOMContentLoaded", scanDomForPasswordForms);
  }

  // 2. Render Full-Screen Red Phishing Blocker Overlay
  function showPhishingBlockerOverlay(data) {
    const existing = document.getElementById("aegis-shield-fullscreen-blocker");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "aegis-shield-fullscreen-blocker";
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, rgba(15, 23, 42, 0.98), rgba(69, 10, 10, 0.97));
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      backdrop-filter: blur(12px);
    `;

    const findingsHtml = (data.findings || [])
      .slice(0, 4)
      .map(
        (f) => `
        <li style="margin-bottom:8px; padding:10px 12px; background:rgba(255,255,255,0.06); border-left:4px solid #ef4444; border-radius:8px; font-size:13px;">
          <strong style="color:#fca5a5;">[${f.severity}] ${f.title}:</strong>
          <span style="color:#e2e8f0; display:block; margin-top:2px;">${f.evidence}</span>
        </li>`
      )
      .join("");

    overlay.innerHTML = `
      <div style="max-width:680px; width:100%; background:#111827; border:2px solid #ef4444; border-radius:20px; padding:28px; box-shadow:0 25px 60px rgba(239,68,68,0.35);">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; border-bottom:1px solid rgba(255,255,255,0.12); padding-bottom:16px;">
          <div style="display:flex; align-items:center; gap:12px;">
            <div style="width:44px; height:44px; border-radius:12px; background:#ef4444; display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:bold;">
              🛡️
            </div>
            <div>
              <div style="font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#fca5a5; font-weight:700;">
                AegisShield Autonomous AI Agent • Active Interception
              </div>
              <h1 style="margin:2px 0 0; font-size:22px; font-weight:800; color:#ffffff;">
                Deceptive / High-Risk Website Blocked
              </h1>
            </div>
          </div>
          <div style="text-align:right; background:rgba(239,68,68,0.18); border:1px solid #ef4444; padding:8px 14px; border-radius:12px;">
            <div style="font-size:20px; font-weight:800; color:#fca5a5; font-family:monospace;">${data.risk_score}/100</div>
            <div style="font-size:11px; font-weight:700; color:#fecaca;">${data.risk_classification}</div>
          </div>
        </div>

        <p style="margin:16px 0 12px; font-size:14px; line-height:1.55; color:#cbd5e1;">
          The Aegis Autonomous Security Agent intercepted navigation to <strong style="color:#fff; font-family:monospace;">${data.primary_target}</strong>.
          <span style="color:#fde047; font-weight:600;">Note: A valid HTTPS/TLS padlock does NOT mean a website is legitimate.</span>
        </p>

        <div style="margin:14px 0;">
          <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.8px; color:#94a3b8; font-weight:700; margin-bottom:8px;">
            Deterministic Technical Evidence (${(data.steps || []).length} Agent Tool Steps Executed)
          </div>
          <ul style="list-style:none; padding:0; margin:0;">
            ${findingsHtml || `<li style="padding:10px; background:rgba(255,255,255,0.06); border-radius:8px; font-size:13px;">High-risk phishing / impersonation heuristics triggered.</li>`}
          </ul>
        </div>

        <div style="padding:10px 12px; background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.35); border-radius:10px; font-size:11px; font-family:monospace; color:#a7f3d0; margin-bottom:18px; word-break:break-all;">
          <strong>Web3 Keccak-256 Proof:</strong> ${data.report_hash_keccak256 || "Anchored"}
        </div>

        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
          <button id="aegis-btn-back-safety" style="flex:1; padding:12px 20px; background:#10b981; color:#052e16; font-weight:800; font-size:14px; border:none; border-radius:12px; cursor:pointer;">
            ← Leave Site Immediately (Back to Safety)
          </button>
          <button id="aegis-btn-proceed-unsafe" style="padding:12px 16px; background:transparent; color:#94a3b8; font-weight:600; font-size:12px; border:1px solid rgba(148,163,184,0.35); border-radius:12px; cursor:pointer;">
            Dismiss Warning (Proceed at Own Risk)
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("aegis-btn-back-safety").addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "http://localhost:8000/agent";
      }
    });

    document.getElementById("aegis-btn-proceed-unsafe").addEventListener("click", () => {
      overlay.remove();
    });
  }

  // 3. Render Floating Mini-Card for Context Menu Investigations
  function showAgentMiniCard(data) {
    const existing = document.getElementById("aegis-shield-minicard");
    if (existing) existing.remove();

    const isHigh = data.risk_score >= 60;
    const isSusp = data.risk_score >= 25 && data.risk_score < 60;
    const borderColor = isHigh ? "#ef4444" : isSusp ? "#f59e0b" : "#10b981";

    const card = document.createElement("div");
    card.id = "aegis-shield-minicard";
    card.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      width: 370px;
      z-index: 2147483646;
      background: #0f172a;
      color: #f8fafc;
      border: 2px solid ${borderColor};
      border-radius: 16px;
      padding: 16px;
      box-shadow: 0 20px 45px rgba(0,0,0,0.55);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
    `;

    card.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:10px;">
        <div style="font-weight:800; font-size:14px; color:#38bdf8;">
          🛡️ Aegis AI Agent Verdict
        </div>
        <button id="aegis-minicard-close" style="background:none; border:none; color:#94a3b8; cursor:pointer; font-size:16px; font-weight:bold;">✕</button>
      </div>
      <div style="display:flex; align-items:center; justify-content:space-between; background:rgba(255,255,255,0.06); padding:8px 12px; border-radius:10px; margin-bottom:10px;">
        <span style="font-family:monospace; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:210px;">${data.primary_target}</span>
        <span style="font-weight:800; color:${borderColor}; font-family:monospace;">${data.risk_score}/100 (${data.risk_classification})</span>
      </div>
      <p style="margin:0 0 10px; font-size:12px; line-height:1.45; color:#cbd5e1;">
        ${data.copilot_reply}
      </p>
      <div style="display:flex; justify-content:space-between; align-items:center; font-size:11px; color:#94a3b8;">
        <span>${(data.steps || []).length} Agent steps completed</span>
        <a href="http://localhost:8000/agent" target="_blank" style="color:#38bdf8; font-weight:700; text-decoration:none;">Open Full Trace →</a>
      </div>
    `;

    document.body.appendChild(card);
    document.getElementById("aegis-minicard-close").addEventListener("click", () => card.remove());
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "AEGIS_BLOCK_PAGE" && msg.data) {
      showPhishingBlockerOverlay(msg.data);
    } else if (msg.type === "AEGIS_SHOW_MINICARD" && msg.data) {
      showAgentMiniCard(msg.data);
    }
  });
})();
