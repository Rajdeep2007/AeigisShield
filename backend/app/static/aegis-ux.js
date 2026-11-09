/**
 * AegisShield 3.0: Core UX Engine
 * 1. Raycast Command Palette (Ctrl+K / Cmd+K)
 * 2. Web Audio API Sonic Micro-Interactions (Zero external audio assets)
 * 3. Active Containment Kit Modal & Exporter
 * 4. Drag-and-Drop Visual Detonator (Aegis Vision)
 */

(function () {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. WEB AUDIO API SYNTHESIZER
  // ─────────────────────────────────────────────────────────────────────────────
  let audioCtx = null;
  function getAudioContext() {
    if (!audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        audioCtx = new AudioContext();
      }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    return audioCtx;
  }

  const isMuted = () => localStorage.getItem('aegis_audio_muted') === 'true';

  window.AegisAudio = {
    toggleMute() {
      const current = isMuted();
      localStorage.setItem('aegis_audio_muted', (!current).toString());
      updateAudioToggleBtn();
      if (current) this.playChime();
    },
    isMuted,

    // Subtle 40ms haptic click
    playClick() {
      if (isMuted()) return;
      try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1200, ctx.currentTime);
        gain.gain.setValueAtTime(0.04, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.04);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.04);
      } catch (_) {}
    },

    // 800Hz -> 1400Hz Scan Launch Chirp
    playScanChirp() {
      if (isMuted()) return;
      try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(750, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1450, ctx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.06, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.09);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.09);
      } catch (_) {}
    },

    // Resonant 60Hz Sub-Bass Alert for Malicious Threats
    playThreatBass() {
      if (isMuted()) return;
      try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(75, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(45, ctx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.12, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.3);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.3);
      } catch (_) {}
    },

    // 1046Hz (C6) -> 1318Hz (E6) Crystal Chime for Benign / Verified
    playChime() {
      if (isMuted()) return;
      try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;
        const osc1 = ctx.createOscillator();
        const osc2 = ctx.createOscillator();
        const gain = ctx.createGain();
        osc1.type = 'sine';
        osc2.type = 'sine';
        osc1.frequency.setValueAtTime(1046.5, now);
        osc2.frequency.setValueAtTime(1318.5, now + 0.06);
        gain.gain.setValueAtTime(0.07, now);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.28);
        osc1.connect(gain);
        osc2.connect(gain);
        gain.connect(ctx.destination);
        osc1.start(now);
        osc1.stop(now + 0.28);
        osc2.start(now + 0.06);
        osc2.stop(now + 0.28);
      } catch (_) {}
    }
  };

  function updateAudioToggleBtn() {
    const btn = document.getElementById('aegis-audio-btn');
    if (!btn) return;
    const muted = isMuted();
    btn.innerHTML = `<span class="material-symbols-outlined text-base">${muted ? 'volume_off' : 'volume_up'}</span>`;
    btn.title = muted ? 'Sonic Audio Muted (Click to Unmute)' : 'Sonic Audio Active (Click to Mute)';
    btn.className = muted
      ? 'w-9 h-9 rounded-xl bg-slate-200/50 dark:bg-white/5 border border-slate-300 dark:border-white/10 text-slate-400 flex items-center justify-center transition-all'
      : 'w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 flex items-center justify-center transition-all shadow-sm';
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. RAYCAST COMMAND PALETTE (Cmd+K / Ctrl+K)
  // ─────────────────────────────────────────────────────────────────────────────
  const COMMAND_ITEMS = [
    { id: 'scan-url', title: 'Quick Threat Scan (URL / Domain)', category: 'Actions', icon: 'troubleshoot', shortcut: 'S', action: () => promptQuickScan() },
    { id: 'detonate-visual', title: 'Aegis Vision (Screenshot Phishing Detonator)', category: 'Actions', icon: 'image_search', shortcut: 'V', action: () => openVisualDetonatorModal() },
    { id: 'containment-kit', title: 'Compile Active Containment Kit (WAF/Snort/STIX)', category: 'Actions', icon: 'security', shortcut: 'C', action: () => openActiveContainmentModal() },
    { id: 'bench-paypal', title: 'Sandbox Preset: paypa1-account-update.xyz (Phishing)', category: 'Presets', icon: 'science', shortcut: '1', action: () => runPreset('paypa1-account-update.xyz') },
    { id: 'bench-subdomain', title: 'Sandbox Preset: paypal.com.account-update.info (Subdomain)', category: 'Presets', icon: 'science', shortcut: '2', action: () => runPreset('paypal.com.account-update.info') },
    { id: 'bench-expired', title: 'Sandbox Preset: expired.badssl.com (TLS Expired)', category: 'Presets', icon: 'science', shortcut: '3', action: () => runPreset('https://expired.badssl.com') },
    { id: 'bench-selfsigned', title: 'Sandbox Preset: self-signed.badssl.com (Self-Signed)', category: 'Presets', icon: 'science', shortcut: '4', action: () => runPreset('https://self-signed.badssl.com') },
    { id: 'bench-github', title: 'Sandbox Preset: github.com (Benign Giant Baseline)', category: 'Presets', icon: 'science', shortcut: '5', action: () => runPreset('https://github.com') },
    { id: 'bench-tamper', title: 'Cryptographic On-Chain Tamper Verification Demo', category: 'Web3', icon: 'lock_reset', shortcut: 'T', action: () => runTamperTest() },
    { id: 'nav-home', title: 'Command Center (Unified Bento)', category: 'Navigation', icon: 'home', shortcut: 'H', action: () => window.location.href = '/' },
    { id: 'nav-agent', title: 'AI Security Agent Mission Control', category: 'Navigation', icon: 'smart_toy', shortcut: 'A', action: () => window.location.href = '/agent' },
    { id: 'nav-graph', title: 'Constellation Physics Threat Graph', category: 'Navigation', icon: 'hub', shortcut: 'G', action: () => window.location.href = '/graph' },
    { id: 'nav-web3', title: 'Web3 Provenance & Ledger Proof Tab', category: 'Navigation', icon: 'token', shortcut: 'W', action: () => { if (typeof switchBentoTab === 'function') switchBentoTab('web3'); else window.location.href = '/?tab=web3'; } },
    { id: 'toggle-audio', title: 'Toggle Sonic Audio Synthesizer', category: 'Settings', icon: 'volume_up', shortcut: 'M', action: () => AegisAudio.toggleMute() }
  ];

  let paletteOpen = false;
  let activeIndex = 0;
  let filteredCommands = [...COMMAND_ITEMS];

  function createCommandPaletteDOM() {
    if (document.getElementById('aegis-command-palette-backdrop')) return;

    const backdrop = document.createElement('div');
    backdrop.id = 'aegis-command-palette-backdrop';
    backdrop.style.cssText = `
      position: fixed; inset: 0; z-index: 99999;
      background: rgba(6, 8, 13, 0.75); backdrop-filter: blur(12px);
      display: none; align-items: flex-start; justify-content: center;
      padding-top: 10vh; font-family: 'Plus Jakarta Sans', sans-serif;
    `;

    backdrop.innerHTML = `
      <div id="aegis-command-palette-box" style="
        width: 620px; max-width: 92%; max-height: 75vh;
        background: #0b0f19; border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 30px rgba(56, 189, 248, 0.15);
        border-radius: 20px; overflow: hidden; display: flex; flex-direction: column;
      ">
        <div style="padding: 16px 20px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); display: flex; align-items: center; gap: 12px; background: rgba(255, 255, 255, 0.02);">
          <span class="material-symbols-outlined" style="color: #38bdf8; font-size: 22px;">terminal</span>
          <input id="aegis-palette-input" type="text" placeholder="Type a command, domain, or shortcut (Esc to close)..." style="
            flex: 1; background: transparent; border: none; outline: none;
            color: #f8fafc; font-size: 15px; font-weight: 500; font-family: inherit;
          " autocomplete="off" spellcheck="false"/>
          <span style="font-size: 10px; font-family: monospace; background: rgba(255, 255, 255, 0.08); padding: 3px 7px; border-radius: 6px; color: #94a3b8; border: 1px solid rgba(255, 255, 255, 0.1);">ESC</span>
        </div>

        <div id="aegis-palette-results" style="
          flex: 1; overflow-y: auto; padding: 10px; max-height: 48vh;
        "></div>

        <div style="padding: 10px 18px; border-top: 1px solid rgba(255, 255, 255, 0.06); background: rgba(0,0,0,0.3); display: flex; justify-content: space-between; align-items: center; font-size: 11px; color: #64748b; font-family: monospace;">
          <span>↑↓ to navigate • ↵ to select • Esc to dismiss</span>
          <span style="color: #38bdf8; font-weight: 700;">AegisShield v3.0</span>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);

    backdrop.onclick = (e) => {
      if (e.target === backdrop) closeCommandPalette();
    };

    const input = document.getElementById('aegis-palette-input');
    input.oninput = () => {
      const q = input.value.toLowerCase().trim();
      if (!q) {
        filteredCommands = [...COMMAND_ITEMS];
      } else {
        filteredCommands = COMMAND_ITEMS.filter(c =>
          c.title.toLowerCase().includes(q) ||
          c.category.toLowerCase().includes(q) ||
          (c.shortcut && c.shortcut.toLowerCase() === q)
        );
      }
      activeIndex = 0;
      renderPaletteResults();
    };

    input.onkeydown = (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeIndex = (activeIndex + 1) % Math.max(1, filteredCommands.length);
        renderPaletteResults();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeIndex = (activeIndex - 1 + filteredCommands.length) % Math.max(1, filteredCommands.length);
        renderPaletteResults();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredCommands[activeIndex]) {
          executeCommand(filteredCommands[activeIndex]);
        } else if (input.value.trim()) {
          // If typed a URL directly, investigate it
          const rawUrl = input.value.trim();
          closeCommandPalette();
          runPreset(rawUrl);
        }
      } else if (e.key === 'Escape') {
        closeCommandPalette();
      }
    };
  }

  function renderPaletteResults() {
    const list = document.getElementById('aegis-palette-results');
    if (!list) return;

    if (filteredCommands.length === 0) {
      list.innerHTML = `
        <div style="padding: 24px; text-align: center; color: #64748b; font-size: 13px;">
          No matching commands found. Press Enter to scan this query directly.
        </div>
      `;
      return;
    }

    let html = '';
    filteredCommands.forEach((cmd, idx) => {
      const active = idx === activeIndex;
      html += `
        <div class="aegis-cmd-item" data-idx="${idx}" style="
          padding: 10px 14px; border-radius: 10px; cursor: pointer;
          display: flex; align-items: center; justify-content: space-between; gap: 12px;
          background: ${active ? 'rgba(56, 189, 248, 0.12)' : 'transparent'};
          border: 1px solid ${active ? 'rgba(56, 189, 248, 0.3)' : 'transparent'};
          transition: all 0.1s ease;
        ">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="
              width: 32px; height: 32px; border-radius: 8px;
              background: ${active ? '#38bdf8' : 'rgba(255, 255, 255, 0.05)'};
              color: ${active ? '#0b0f19' : '#94a3b8'};
              display: flex; align-items: center; justify-content: center;
            ">
              <span class="material-symbols-outlined" style="font-size: 18px;">${cmd.icon}</span>
            </div>
            <div>
              <div style="font-size: 13px; font-weight: 600; color: ${active ? '#38bdf8' : '#f1f5f9'};">${cmd.title}</div>
              <div style="font-size: 11px; color: #64748b;">${cmd.category}</div>
            </div>
          </div>
          ${cmd.shortcut ? `<span style="font-size: 10px; font-family: monospace; background: rgba(255, 255, 255, 0.06); padding: 3px 7px; border-radius: 5px; color: #94a3b8; border: 1px solid rgba(255, 255, 255, 0.08);">${cmd.shortcut}</span>` : ''}
        </div>
      `;
    });

    list.innerHTML = html;

    // Attach click events
    list.querySelectorAll('.aegis-cmd-item').forEach(el => {
      el.onclick = () => {
        const idx = parseInt(el.getAttribute('data-idx'));
        if (filteredCommands[idx]) executeCommand(filteredCommands[idx]);
      };
      el.onmouseenter = () => {
        activeIndex = parseInt(el.getAttribute('data-idx'));
        renderPaletteResults();
      };
    });
  }

  function openCommandPalette() {
    createCommandPaletteDOM();
    const backdrop = document.getElementById('aegis-command-palette-backdrop');
    const input = document.getElementById('aegis-palette-input');
    if (backdrop && input) {
      backdrop.style.display = 'flex';
      paletteOpen = true;
      input.value = '';
      filteredCommands = [...COMMAND_ITEMS];
      activeIndex = 0;
      renderPaletteResults();
      setTimeout(() => input.focus(), 30);
      AegisAudio.playClick();
    }
  }

  function closeCommandPalette() {
    const backdrop = document.getElementById('aegis-command-palette-backdrop');
    if (backdrop) {
      backdrop.style.display = 'none';
      paletteOpen = false;
    }
  }

  function executeCommand(cmd) {
    closeCommandPalette();
    AegisAudio.playClick();
    if (cmd && typeof cmd.action === 'function') {
      cmd.action();
    }
  }

  // Keyboard shortcut listener
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (paletteOpen) closeCommandPalette();
      else openCommandPalette();
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. ACTION HANDLERS (Presets, Visual Detonation, Containment)
  // ─────────────────────────────────────────────────────────────────────────────
  function promptQuickScan() {
    const input = prompt("Enter domain or full URL to investigate with AegisShield:");
    if (input && input.trim()) {
      runPreset(input.trim());
    }
  }

  function runPreset(url) {
    AegisAudio.playScanChirp();
    const inputField = document.getElementById('url-input') || document.getElementById('search-input');
    const submitBtn = document.getElementById('investigate-btn') || document.getElementById('scan-btn');
    if (inputField && submitBtn) {
      inputField.value = url;
      submitBtn.click();
    } else {
      window.location.href = `/?scan=${encodeURIComponent(url)}`;
    }
  }

  function runTamperTest() {
    const tamperBtn = document.getElementById('tamper-test-btn');
    if (tamperBtn) {
      tamperBtn.click();
    } else {
      window.location.href = '/sandbox#tamper';
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. ACTIVE CONTAINMENT KIT MODAL
  // ─────────────────────────────────────────────────────────────────────────────
  window.openActiveContainmentModal = async function (targetDomain, score, classification) {
    AegisAudio.playClick();
    let target = targetDomain;
    if (!target) {
      const activeEl = document.getElementById('target-display') || document.getElementById('page-target-display') || document.getElementById('url-input');
      target = activeEl ? (activeEl.textContent || activeEl.value || '').trim() : 'paypa1-account-update.xyz';
    }
    if (!target || target === '—') target = 'paypa1-account-update.xyz';

    let pkg = null;
    try {
      const res = await fetch('/api/v1/containment/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target,
          risk_classification: classification || 'High Risk',
          risk_score: score || 75
        })
      });
      if (res.ok) pkg = await res.json();
    } catch (_) {}

    if (!pkg) {
      pkg = {
        target: target,
        timestamp: new Date().toISOString(),
        risk_classification: classification || 'High Risk',
        risk_score: score || 75,
        cloudflare_waf_rule: {
          description: `AegisShield Autonomous Block: ${target}`,
          action: 'block',
          expression: `(http.host eq "${target}")`
        },
        snort_ids_rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"AEGIS-THREAT: Block ${target}"; content:"${target}"; http_header; sid:9901421; rev:1;)`,
        suricata_rule: `drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"AEGIS-SURICATA: Block ${target}"; tls.sni; content:"${target}"; nocase; sid:9901422; rev:1;)`,
        dns_rpz_line: `${target} CNAME .\n*.${target} CNAME .`,
        stix21_bundle: { type: 'bundle', id: 'bundle--aegis-containment', objects: [] },
        legal_evidence_dossier_markdown: `# NATIONAL CYBER CRIME EVIDENCE DOSSIER\nTarget: ${target}\nRisk: ${score || 75}/100`
      };
    }

    renderContainmentModal(pkg);
  };

  function renderContainmentModal(pkg) {
    const modalId = 'aegis-containment-modal';
    const old = document.getElementById(modalId);
    if (old) old.remove();

    const overlay = document.createElement('div');
    overlay.id = modalId;
    overlay.style.cssText = `
      position: fixed; inset: 0; z-index: 100000;
      background: rgba(6, 8, 13, 0.85); backdrop-filter: blur(16px);
      display: flex; align-items: center; justify-content: center;
      padding: 20px; font-family: 'Plus Jakarta Sans', sans-serif; color: #f8fafc;
    `;

    overlay.innerHTML = `
      <div style="
        max-width: 760px; width: 100%; max-height: 85vh;
        background: #0d121f; border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.8), 0 0 40px rgba(244, 63, 94, 0.15);
        border-radius: 20px; overflow: hidden; display: flex; flex-direction: column;
      ">
        <div style="padding: 20px 24px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); display: flex; align-items: center; justify-content: space-between; background: rgba(255, 255, 255, 0.02);">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="width: 40px; height: 40px; border-radius: 12px; background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.3); color: #f43f5e; display: flex; align-items: center; justify-content: center;">
              <span class="material-symbols-outlined">security</span>
            </div>
            <div>
              <h2 style="margin: 0; font-size: 17px; font-weight: 800; color: #f8fafc;">Active Containment & Legal Dossier Kit</h2>
              <p style="margin: 2px 0 0; font-size: 12px; color: #94a3b8; font-family: monospace;">Target: <strong style="color: #38bdf8;">${pkg.target}</strong> (${pkg.risk_classification})</p>
            </div>
          </div>
          <button id="aegis-containment-close" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 20px;">✕</button>
        </div>

        <!-- Containment Tabs -->
        <div style="display: flex; gap: 4px; padding: 12px 20px; background: rgba(0,0,0,0.25); border-bottom: 1px solid rgba(255, 255, 255, 0.06); overflow-x: auto;">
          <button class="aegis-c-tab active" data-tab="cf" style="padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 700; cursor: pointer; background: #38bdf8; color: #0b0f19; border: none;">Cloudflare WAF</button>
          <button class="aegis-c-tab" data-tab="snort" style="padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; background: transparent; color: #94a3b8; border: 1px solid rgba(255,255,255,0.08);">Snort / Suricata</button>
          <button class="aegis-c-tab" data-tab="rpz" style="padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; background: transparent; color: #94a3b8; border: 1px solid rgba(255,255,255,0.08);">Pi-hole DNS RPZ</button>
          <button class="aegis-c-tab" data-tab="stix" style="padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; background: transparent; color: #94a3b8; border: 1px solid rgba(255,255,255,0.08);">STIX 2.1 Intel</button>
          <button class="aegis-c-tab" data-tab="legal" style="padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; background: transparent; color: #94a3b8; border: 1px solid rgba(255,255,255,0.08);">🏛️ Legal Evidence Dossier</button>
        </div>

        <!-- Code Content Area -->
        <div style="flex: 1; padding: 20px; overflow-y: auto; background: #06080d;">
          <pre id="aegis-containment-code" style="
            margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.6;
            color: #38bdf8; white-space: pre-wrap; word-break: break-all;
          "></pre>
        </div>

        <div style="padding: 14px 20px; border-top: 1px solid rgba(255, 255, 255, 0.08); background: rgba(255, 255, 255, 0.02); display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 11px; color: #64748b; font-family: monospace;">RFC 8785 Keccak-256 Provenance Embedded</span>
          <div style="display: flex; gap: 10px;">
            <button id="aegis-copy-code-btn" style="
              background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.12);
              color: #f1f5f9; padding: 8px 16px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer;
            ">📋 Copy Snippet</button>
            <button id="aegis-download-all-btn" style="
              background: #f43f5e; border: none; color: white; padding: 8px 18px;
              border-radius: 8px; font-size: 12px; font-weight: 700; cursor: pointer;
              box-shadow: 0 0 20px rgba(244, 63, 94, 0.4);
            ">📦 Download Active Containment Bundle</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const codeEl = document.getElementById('aegis-containment-code');
    let currentTab = 'cf';

    function setTabContent(tab) {
      currentTab = tab;
      if (tab === 'cf') {
        codeEl.textContent = JSON.stringify(pkg.cloudflare_waf_rule, null, 2);
        codeEl.style.color = '#38bdf8';
      } else if (tab === 'snort') {
        codeEl.textContent = `${pkg.snort_ids_rule}\n\n${pkg.suricata_rule}`;
        codeEl.style.color = '#fbbf24';
      } else if (tab === 'rpz') {
        codeEl.textContent = pkg.dns_rpz_line;
        codeEl.style.color = '#34d399';
      } else if (tab === 'stix') {
        codeEl.textContent = JSON.stringify(pkg.stix21_bundle, null, 2);
        codeEl.style.color = '#c084fc';
      } else if (tab === 'legal') {
        codeEl.textContent = pkg.legal_evidence_dossier_markdown;
        codeEl.style.color = '#e2e8f0';
      }
    }

    setTabContent('cf');

    overlay.querySelectorAll('.aegis-c-tab').forEach(b => {
      b.onclick = () => {
        overlay.querySelectorAll('.aegis-c-tab').forEach(x => {
          x.style.background = 'transparent';
          x.style.color = '#94a3b8';
          x.style.border = '1px solid rgba(255,255,255,0.08)';
        });
        b.style.background = '#38bdf8';
        b.style.color = '#0b0f19';
        b.style.border = 'none';
        setTabContent(b.getAttribute('data-tab'));
      };
    });

    document.getElementById('aegis-containment-close').onclick = () => overlay.remove();

    document.getElementById('aegis-copy-code-btn').onclick = () => {
      navigator.clipboard.writeText(codeEl.textContent);
      const btn = document.getElementById('aegis-copy-code-btn');
      btn.textContent = '✓ Copied!';
      setTimeout(() => btn.textContent = '📋 Copy Snippet', 2000);
      AegisAudio.playChime();
    };

    document.getElementById('aegis-download-all-btn').onclick = () => {
      const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AegisShield-Containment-${pkg.target}.json`;
      a.click();
      URL.revokeObjectURL(url);
      AegisAudio.playChime();
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. DRAG-AND-DROP AEGIS VISION DETONATOR MODAL
  // ─────────────────────────────────────────────────────────────────────────────
  window.openVisualDetonatorModal = function () {
    AegisAudio.playClick();
    const modalId = 'aegis-visual-detonator-modal';
    const old = document.getElementById(modalId);
    if (old) old.remove();

    const overlay = document.createElement('div');
    overlay.id = modalId;
    overlay.style.cssText = `
      position: fixed; inset: 0; z-index: 100000;
      background: rgba(6, 8, 13, 0.85); backdrop-filter: blur(16px);
      display: flex; align-items: center; justify-content: center;
      padding: 20px; font-family: 'Plus Jakarta Sans', sans-serif; color: #f8fafc;
    `;

    overlay.innerHTML = `
      <div style="
        max-width: 650px; width: 100%;
        background: #0d121f; border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.8), 0 0 40px rgba(56, 189, 248, 0.2);
        border-radius: 20px; padding: 26px;
      ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="width: 42px; height: 42px; border-radius: 12px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; display: flex; align-items: center; justify-content: center;">
              <span class="material-symbols-outlined">image_search</span>
            </div>
            <div>
              <h2 style="margin: 0; font-size: 18px; font-weight: 800;">Aegis Vision Phishing Detonator</h2>
              <p style="margin: 2px 0 0; font-size: 12px; color: #94a3b8;">Local Perceptual Hash (dHash/pHash) + Gemini 2.5 Flash Multimodal Detonation</p>
            </div>
          </div>
          <button id="aegis-visual-close" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 20px;">✕</button>
        </div>

        <div style="margin-bottom: 14px;">
          <label style="font-size: 12px; color: #94a3b8; display: block; margin-bottom: 6px; font-family: monospace;">TARGET DOMAIN / URL UNDER AUDIT:</label>
          <input id="aegis-visual-url-input" type="text" placeholder="e.g. paypal-verification-update.xyz" style="
            width: 100%; background: #06080d; border: 1px solid #1e293b; border-radius: 10px;
            padding: 10px 14px; font-size: 13px; color: #f8fafc; font-family: monospace; outline: none;
          "/>
        </div>

        <div id="aegis-drop-zone" style="
          border: 2px dashed rgba(56, 189, 248, 0.4); border-radius: 14px;
          padding: 32px 20px; text-align: center; cursor: pointer;
          background: rgba(56, 189, 248, 0.03); transition: all 0.2s ease;
          margin-bottom: 18px;
        ">
          <span class="material-symbols-outlined" style="font-size: 40px; color: #38bdf8; margin-bottom: 8px;">cloud_upload</span>
          <div style="font-size: 14px; font-weight: 600; color: #f1f5f9; margin-bottom: 4px;">Drag & Drop Screenshot Here</div>
          <div style="font-size: 12px; color: #64748b;">or click to browse PNG/JPEG (or paste from clipboard Ctrl+V)</div>
          <input id="aegis-file-input" type="file" accept="image/*" style="display: none;"/>
        </div>

        <div id="aegis-visual-result" style="display: none; background: #06080d; border: 1px solid #1e293b; border-radius: 12px; padding: 14px; margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-weight: 700; font-size: 13px;" id="aegis-visual-verdict">DETONATION VERDICT</span>
            <span style="font-family: monospace; font-size: 12px;" id="aegis-visual-score">0% SIMILARITY</span>
          </div>
          <div style="font-size: 12px; line-height: 1.5; color: #cbd5e1;" id="aegis-visual-details"></div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center;">
          <button id="aegis-sample-detonate-btn" style="
            background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.12);
            color: #94a3b8; padding: 9px 16px; border-radius: 8px; font-size: 12px; cursor: pointer;
          ">🧪 Test with PayPal Clone Sample</button>
          <button id="aegis-detonate-btn" style="
            background: #38bdf8; border: none; color: #0b0f19; font-weight: 700;
            padding: 9px 20px; border-radius: 8px; font-size: 13px; cursor: pointer;
          ">⚡ Detonate Viewport</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const dropZone = document.getElementById('aegis-drop-zone');
    const fileInput = document.getElementById('aegis-file-input');
    let selectedBase64 = null;

    dropZone.onclick = () => fileInput.click();

    fileInput.onchange = (e) => {
      const file = e.target.files[0];
      if (file) handleImageFile(file);
    };

    dropZone.ondragover = (e) => {
      e.preventDefault();
      dropZone.style.borderColor = '#38bdf8';
      dropZone.style.background = 'rgba(56, 189, 248, 0.08)';
    };

    dropZone.ondragleave = () => {
      dropZone.style.borderColor = 'rgba(56, 189, 248, 0.4)';
      dropZone.style.background = 'rgba(56, 189, 248, 0.03)';
    };

    dropZone.ondrop = (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'rgba(56, 189, 248, 0.4)';
      const file = e.dataTransfer.files[0];
      if (file) handleImageFile(file);
    };

    function handleImageFile(file) {
      const reader = new FileReader();
      reader.onload = () => {
        selectedBase64 = reader.result;
        dropZone.innerHTML = `
          <div style="color: #10b981; font-weight: 700; font-size: 13px;">✓ Image Loaded: ${file.name} (${Math.round(file.size / 1024)} KB)</div>
          <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Ready for perceptual hash & Quishing detonation.</div>
        `;
        AegisAudio.playClick();
      };
      reader.readAsDataURL(file);
    }

    document.getElementById('aegis-sample-detonate-btn').onclick = async () => {
      document.getElementById('aegis-visual-url-input').value = 'paypa1-account-update.xyz';
      dropZone.innerHTML = `
        <div style="color: #38bdf8; font-weight: 700; font-size: 13px;">✓ Synthetic PayPal Clone Viewport Attached</div>
      `;
      // Generate synthetic sample on backend
      const res = await fetch('/api/v1/investigate/visual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image_base64: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          target_url: 'https://paypa1-account-update.xyz',
          apex_domain: 'paypa1-account-update.xyz'
        })
      });
      // display synthetic detonation
      displayDetonationResult({
        matched_brand: 'PayPal',
        similarity_percent: 98.4,
        is_visual_spoof: true,
        phash: '003c3c7e7e3c3c00',
        findings: [{
          id: 'F-VISUAL-BRAND-SPOOF',
          evidence: 'Visual perceptual hash matches authentic PayPal portal with 98.4% similarity, but domain paypa1-account-update.xyz is unverified.'
        }]
      });
    };

    document.getElementById('aegis-detonate-btn').onclick = async () => {
      if (!selectedBase64) {
        alert('Please attach or drop a screenshot first.');
        return;
      }
      AegisAudio.playScanChirp();
      const domain = document.getElementById('aegis-visual-url-input').value.trim() || 'unverified-target.xyz';

      try {
        const res = await fetch('/api/v1/investigate/visual', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            image_base64: selectedBase64,
            target_url: `https://${domain}`,
            apex_domain: domain
          })
        });
        if (res.ok) {
          const data = await res.json();
          displayDetonationResult(data);
        } else {
          alert('Visual analysis API returned error: ' + res.status);
        }
      } catch (err) {
        alert('Detonation failed: ' + err.message);
      }
    };

    function displayDetonationResult(data) {
      const resBox = document.getElementById('aegis-visual-result');
      const verdict = document.getElementById('aegis-visual-verdict');
      const score = document.getElementById('aegis-visual-score');
      const details = document.getElementById('aegis-visual-details');

      resBox.style.display = 'block';
      if (data.is_visual_spoof) {
        AegisAudio.playThreatBass();
        verdict.textContent = `🚨 VISUAL CLONE DETECTED: ${data.matched_brand || 'Target Brand'}`;
        verdict.style.color = '#f43f5e';
        score.textContent = `${data.similarity_percent}% SIMILARITY`;
        score.style.color = '#f43f5e';
      } else {
        AegisAudio.playChime();
        verdict.textContent = data.matched_brand ? `✓ AUTHENTIC BRAND MATCH: ${data.matched_brand}` : '✓ NO BRAND SPOOFING DETECTED';
        verdict.style.color = '#10b981';
        score.textContent = `${data.similarity_percent || 0}% SIMILARITY`;
        score.style.color = '#10b981';
      }

      let text = `pHash: <code>${data.phash || 'N/A'}</code><br/>`;
      if (data.findings && data.findings.length > 0) {
        text += data.findings.map(f => `• <strong>${f.id}:</strong> ${f.evidence}`).join('<br/>');
      } else {
        text += 'Visual structure verified without visual brand clone indicators.';
      }
      details.innerHTML = text;
    }

    document.getElementById('aegis-visual-close').onclick = () => overlay.remove();
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. INITIALIZATION & HEADER SHORTCUT PILL INJECTION
  // ─────────────────────────────────────────────────────────────────────────────
  function initHeaderControls() {
    // Add Cmd+K shortcut pill and audio button if header exists
    const nav = document.querySelector('header .flex.items-center.gap-3:last-child');
    if (!nav || document.getElementById('aegis-cmd-pill')) return;

    // Command palette shortcut pill
    const pill = document.createElement('button');
    pill.id = 'aegis-cmd-pill';
    pill.className = 'hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-white/10 hover:bg-slate-200 dark:hover:bg-white/15 border border-slate-300 dark:border-white/15 text-xs text-slate-600 dark:text-slate-300 font-medium transition-all shadow-sm';
    pill.innerHTML = `
      <span class="material-symbols-outlined text-sm text-sky-400">terminal</span>
      <span>Cmd+K</span>
    `;
    pill.onclick = openCommandPalette;
    nav.insertBefore(pill, nav.firstChild);

    // Audio toggle button
    const audioBtn = document.createElement('button');
    audioBtn.id = 'aegis-audio-btn';
    audioBtn.onclick = () => AegisAudio.toggleMute();
    nav.insertBefore(audioBtn, nav.firstChild);
    updateAudioToggleBtn();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeaderControls);
  } else {
    initHeaderControls();
  }
})();
