document.addEventListener('DOMContentLoaded', async () => {
    const statusBox = document.getElementById('statusBox');
    const statusText = document.getElementById('statusText');
    const statusIcon = document.getElementById('statusIcon');
    const urlDisplay = document.getElementById('urlDisplay');
    const rescanBtn = document.getElementById('rescanBtn');

    async function scanCurrentTab() {
        // Find active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url.startsWith('http')) {
            statusText.innerText = 'NOT SCANNING';
            urlDisplay.innerText = 'Visit a website to start scan.';
            return;
        }

        urlDisplay.innerText = new URL(tab.url).hostname;
        statusText.innerText = 'ANALYZING...';
        statusIcon.innerText = '⚙️';

        try {
            const response = await fetch('http://localhost:8000/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `url=${encodeURIComponent(tab.url)}`
            });
            const result = await response.json();
            
            // Update UI State
            document.body.className = `status-${result.status}`;
            statusText.innerText = result.status;
            statusIcon.innerText = result.status === 'REAL' ? '✅' : (result.status === 'FAKE' ? '❌' : '⚠️');
            
        } catch (err) {
            statusText.innerText = 'SERVER OFFLINE';
            statusIcon.innerText = '🔌';
            urlDisplay.innerText = 'Start main.py to enable scanning.';
        }
    }

    rescanBtn.addEventListener('click', scanCurrentTab);
    scanCurrentTab();
});
