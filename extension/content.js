chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showWarning') {
    renderOverlay(request.result);
  }
});

// Check status on load
chrome.runtime.sendMessage({ action: 'checkCurrentTab' }, (response) => {
  if (response && response.status === 'found') {
    const result = response.result;
    if (result.status === 'FAKE' || result.status === 'SUSPICIOUS') {
      renderOverlay(result);
    }
  }
});

function renderOverlay(data) {
  // Check if overlay already exists
  if (document.getElementById('guardlink-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'guardlink-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.9);
    z-index: 2147483647;
    display: flex;
    justify-content: center;
    align-items: center;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    color: white;
    backdrop-filter: blur(10px);
  `;

  const warningCard = document.createElement('div');
  warningCard.style.cssText = `
    background: #1a1a1a;
    border: 2px solid ${data.status === 'FAKE' ? '#ff4b2b' : '#ffb300'};
    padding: 3rem;
    border-radius: 20px;
    max-width: 500px;
    text-align: center;
    box-shadow: 0 10px 50px rgba(0,0,0,0.5);
    animation: slideIn 0.5s ease-out;
  `;

  const style = document.createElement('style');
  style.innerHTML = `
    @keyframes slideIn {
      from { transform: translateY(50px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .gl-btn {
      padding: 0.8rem 1.5rem;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      margin: 10px;
      transition: all 0.3s;
      border: none;
    }
    .gl-btn-primary { background: ${data.status === 'FAKE' ? '#ff4b2b' : '#ffb300'}; color: white; }
    .gl-btn-secondary { background: #333; color: #ccc; }
    .gl-btn:hover { transform: scale(1.05); filter: brightness(1.2); }
  `;
  document.head.appendChild(style);

  warningCard.innerHTML = `
    <div style="font-size: 5rem; margin-bottom: 1rem;">⚠️</div>
    <h1 style="font-size: 2rem; color: ${data.status === 'FAKE' ? '#ff4b2b' : '#ffb300'}; margin: 0;">${data.status} WEBSITE DETECTED</h1>
    <p style="font-size: 1.1rem; color: #ccc; margin: 1.5rem 0;">Our analysis indicates this site may be unsafe.</p>
    <div style="background: #252525; padding: 1rem; border-radius: 10px; margin-bottom: 2rem; text-align: left;">
      <p style="margin: 0; color: #888; font-size: 0.9rem;">REASON:</p>
      <p style="margin: 5px 0 0 0; color: #eee;">${data.warnings[0]}</p>
    </div>
    <div style="display: flex; justify-content: center;">
      <button id="gl-continue" class="gl-btn gl-btn-secondary">Proceed Anyway (Unsafe)</button>
      <button id="gl-leave" class="gl-btn gl-btn-primary">Leave Site Now</button>
    </div>
  `;

  overlay.appendChild(warningCard);
  document.body.appendChild(overlay);

  document.getElementById('gl-leave').addEventListener('click', () => {
    window.location.href = 'https://www.google.com';
  });

  document.getElementById('gl-continue').addEventListener('click', () => {
    overlay.style.display = 'none';
  });
}
