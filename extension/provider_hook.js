/**
 * AegisShield 3.0: In-Page Web3 EIP-712 & Permit2 Drainer Interceptor.
 * Runs in the page's MAIN execution world at document_start.
 * Intercepts off-chain signatures that wallet simulators fail to detect.
 */

(function () {
  'use strict';

  if (window.__AEGIS_WEB3_HOOK_INSTALLED__) return;
  window.__AEGIS_WEB3_HOOK_INSTALLED__ = true;

  console.log('[AegisShield] Web3 Permit2 & EIP-712 Signature Interceptor active.');

  // Known drainer contract signatures and high-risk Permit2 patterns
  const PERMIT2_TYPES = [
    'PermitTransferFrom',
    'PermitWitnessTransferFrom',
    'PermitSingle',
    'PermitBatch',
    'PermitDetails',
    'TokenPermissions'
  ];

  const UNLIMITED_ALLOWANCES = [
    '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    '115792089237316195423570985008687907853269984665640564039457584007913129639935',
    '1000000000000000000000000000000000000000000'
  ];

  function inspectTypedData(params) {
    try {
      if (!params || params.length < 2) return null;
      let typedData = params[1];
      if (typeof typedData === 'string') {
        typedData = JSON.parse(typedData);
      }

      const primaryType = typedData.primaryType || '';
      const types = typedData.types || {};
      const message = typedData.message || {};
      const domain = typedData.domain || {};

      let isPermit2 = false;
      let isUnlimited = false;
      let spender = message.spender || (message.details && message.details.spender) || message.operator || 'Unknown';
      let token = message.token || (message.details && message.details.token) || domain.verifyingContract || 'Unknown';

      // Check primaryType or types
      if (PERMIT2_TYPES.includes(primaryType) || primaryType.toLowerCase().includes('permit')) {
        isPermit2 = true;
      }
      for (const t of Object.keys(types)) {
        if (PERMIT2_TYPES.includes(t)) {
          isPermit2 = true;
          break;
        }
      }

      // Check amount / allowance
      const amountStr = String(message.amount || (message.details && message.details.amount) || message.value || '');
      if (UNLIMITED_ALLOWANCES.some(unlim => amountStr.toLowerCase().includes(unlim.toLowerCase()))) {
        isUnlimited = true;
      }
      if (amountStr.length >= 30) {
        isUnlimited = true;
      }

      if (isPermit2 || isUnlimited) {
        return {
          isPermit2,
          isUnlimited,
          primaryType,
          spender,
          token,
          domainName: domain.name || 'Unknown',
          chainId: domain.chainId || 'Unknown'
        };
      }
    } catch (e) {
      console.warn('[AegisShield] EIP-712 parse error:', e);
    }
    return null;
  }

  function showPermit2WarningModal(details) {
    return new Promise((resolve) => {
      const modalId = '__aegis_permit2_modal__';
      const existing = document.getElementById(modalId);
      if (existing) existing.remove();

      const overlay = document.createElement('div');
      overlay.id = modalId;
      overlay.style.cssText = `
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        background: rgba(7, 9, 14, 0.94);
        backdrop-filter: blur(16px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #f8fafc;
      `;

      overlay.innerHTML = `
        <div style="
          max-width: 520px;
          width: 90%;
          background: #0f172a;
          border: 1px solid rgba(239, 68, 68, 0.4);
          box-shadow: 0 0 50px rgba(239, 68, 68, 0.25);
          border-radius: 16px;
          padding: 28px;
          text-align: left;
        ">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
            <div style="width: 44px; height: 44px; border-radius: 12px; background: rgba(239, 68, 68, 0.2); display: flex; align-items: center; justify-content: center; color: #ef4444; font-size: 24px;">
              ⚠️
            </div>
            <div>
              <h2 style="margin: 0; font-size: 19px; font-weight: 700; color: #f87171;">CRITICAL PERMIT2 DRAINER INTERCEPTED</h2>
              <p style="margin: 2px 0 0; font-size: 12px; color: #94a3b8;">AegisShield EIP-712 Autonomous Pre-Sign Guard</p>
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 14px; margin-bottom: 18px; font-size: 13px; line-height: 1.5;">
            <div style="color: #cbd5e1; margin-bottom: 8px;">
              This website requested an <strong>off-chain EIP-712 signature</strong> granting authorization to transfer your wallet tokens without further transaction approval:
            </div>
            <div style="font-family: monospace; font-size: 11px; background: #020617; padding: 10px; border-radius: 6px; border: 1px solid #1e293b; color: #38bdf8; word-break: break-all;">
              <div><strong>Signature Type:</strong> ${details.primaryType}</div>
              <div><strong>Spender Address:</strong> ${details.spender}</div>
              <div><strong>Verifying Contract:</strong> ${details.token}</div>
              <div><strong>Allowance Scope:</strong> ${details.isUnlimited ? 'UNLIMITED (100% Wallet Exposure)' : 'Batch Transfer'}</div>
            </div>
            <div style="margin-top: 8px; font-size: 11px; color: #fca5a5;">
              ⚠️ Standard wallet simulators (MetaMask, Phantom) often report this as <strong>"0 ETH Movement / Safe"</strong> because the token transfer executes in a secondary transaction.
            </div>
          </div>

          <div style="display: flex; gap: 12px; justify-content: flex-end;">
            <button id="__aegis_override_btn" style="
              background: transparent;
              border: 1px solid #334155;
              color: #94a3b8;
              padding: 9px 16px;
              border-radius: 8px;
              font-size: 12px;
              cursor: pointer;
            ">Override & Sign Anyway</button>
            <button id="__aegis_abort_btn" style="
              background: #ef4444;
              border: none;
              color: white;
              padding: 9px 20px;
              border-radius: 8px;
              font-weight: 600;
              font-size: 13px;
              cursor: pointer;
              box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
            ">🛡️ Block Signature (Recommended)</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      document.getElementById('__aegis_abort_btn').onclick = () => {
        overlay.remove();
        resolve(false);
      };

      document.getElementById('__aegis_override_btn').onclick = () => {
        overlay.remove();
        resolve(true);
      };
    });
  }

  function hookProvider(provider) {
    if (!provider || provider.__aegis_hooked__) return;
    provider.__aegis_hooked__ = true;

    const originalRequest = provider.request.bind(provider);

    provider.request = async function (args) {
      if (!args || !args.method) return originalRequest(args);

      const method = args.method;
      if (
        method === 'eth_signTypedData_v4' ||
        method === 'eth_signTypedData_v3' ||
        method === 'eth_signTypedData'
      ) {
        const details = inspectTypedData(args.params);
        if (details) {
          console.warn('[AegisShield] Malicious Permit2 / EIP-712 drain pattern detected:', details);
          window.dispatchEvent(
            new CustomEvent('AEGIS_WEB3_DRAINER_DETECTED', { detail: details })
          );

          const allow = await showPermit2WarningModal(details);
          if (!allow) {
            throw new Error(
              'AegisShield Security Alert: Off-chain EIP-712 Permit2 signature aborted by user protection policy.'
            );
          }
        }
      }

      return originalRequest(args);
    };
  }

  // Hook immediately if already present
  if (window.ethereum) {
    hookProvider(window.ethereum);
  }

  // Listen for dynamic injection by Web3 wallets
  let currentEthereum = window.ethereum;
  Object.defineProperty(window, 'ethereum', {
    configurable: true,
    enumerable: true,
    get() {
      return currentEthereum;
    },
    set(val) {
      currentEthereum = val;
      hookProvider(val);
    }
  });

  window.addEventListener('ethereum#initialized', () => {
    if (window.ethereum) hookProvider(window.ethereum);
  });
})();
