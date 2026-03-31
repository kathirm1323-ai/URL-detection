let analysisResults = new Map();

chrome.webNavigation.onCommitted.addListener((details) => {
  // frameId 0 means it's the main frame, not an iframe
  if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
    analyzeUrl(details.tabId, details.url);
  }
});

async function analyzeUrl(tabId, url) {
  console.log(`Starting automated scan for: ${url}`);
  // Only skip the main analyzer home page; allow scanning our local phishing test
  if (url === 'http://localhost:8000/' || url === 'http://localhost:8000') return;

  try {
    const response = await fetch('http://localhost:8000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!response.ok) return;

    const result = await response.json();
    console.log('Analysis result for', url, ':', result);

    // Cache the result for this tab
    analysisResults.set(tabId, result);

    if (result.status === 'FAKE' || result.status === 'SUSPICIOUS') {
      // Push the message if the content script is already there
      chrome.tabs.sendMessage(tabId, { action: 'showWarning', result }).catch(() => {
        // Content script might not be loaded yet, which is fine since it will 'pull' later
      });
    }
  } catch (err) {
    console.log('Backend not reachable or error:', err);
  }
}

// Handshake listener: content script asks for its status on load
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkCurrentTab' && sender.tab) {
    const result = analysisResults.get(sender.tab.id);
    if (result) {
      sendResponse({ status: 'found', result });
    } else {
      sendResponse({ status: 'not_found' });
    }
  }
  return true; // Keep message channel open for async responses
});

// Clear cache when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  analysisResults.delete(tabId);
});
