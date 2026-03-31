document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = scanBtn.querySelector('.btn-text');
    const loader = scanBtn.querySelector('.loader-dots');
    const resultContainer = document.getElementById('resultContainer');

    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }

        // State: Loading
        btnText.style.display = 'none';
        loader.style.display = 'flex';
        scanBtn.disabled = true;
        resultContainer.style.display = 'none';

        try {
            const formData = new FormData();
            formData.append('url', url);

            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Analysis failed');

            const data = await response.json();
            renderResult(data);
        } catch (error) {
            console.error(error);
            alert('Error connecting to the analysis server.');
        } finally {
            btnText.style.display = 'block';
            loader.style.display = 'none';
            scanBtn.disabled = false;
        }
    });

    function renderResult(data) {
        const riskClass = data.status.toLowerCase();
        const actionClass = data.risk_level === 'HIGH' ? 'avoid' : (data.risk_level === 'LOW' ? 'safe' : 'verify');
        
        resultContainer.innerHTML = `
            <div class="report-card">
                <div class="report-header">
                    <h2>🔍 URL Security Report</h2>
                    <span class="status-badge ${riskClass}">${data.status}</span>
                </div>

                <div class="report-grid">
                    <div class="grid-item">
                        <h3>🌐 URL Analyzed</h3>
                        <p>${data.url}</p>
                    </div>
                    <div class="grid-item">
                        <h3>🔥 Risk Level</h3>
                        <p style="color: var(--color-${riskClass})">${data.risk_level}</p>
                    </div>
                    <div class="grid-item">
                        <h3>📊 Confidence</h3>
                        <p>${data.confidence}%</p>
                    </div>
                </div>

                <div class="analysis-details">
                    <h3>🧠 Analysis Summary</h3>
                    <p>${data.summary}</p>
                    
                    <div style="margin-top: 1.5rem;">
                        <h3>🚨 Detected Issues & Findings</h3>
                        <ul class="findings-list">
                            ${data.findings.map(f => `<li>${f}</li>`).join('')}
                        </ul>
                        <ul class="warnings-list">
                            ${data.warnings.map(w => `<li>${w}</li>`).join('')}
                        </ul>
                    </div>
                </div>

                <div class="final-action ${actionClass}">
                    ✅ RECOMMENDED ACTION: ${data.advice}
                </div>
            </div>
        `;
        resultContainer.style.display = 'block';
        resultContainer.scrollIntoView({ behavior: 'smooth' });
    }
});
