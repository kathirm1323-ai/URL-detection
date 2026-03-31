import uvicorn
import multipart
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import tldextract
import re
import requests
import whois
from datetime import datetime

# Trusted high-reputation domains to avoid false positives
TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'microsoft.com', 'apple.com', 'github.com', 
    'amazon.com', 'amazon.in', 'linkedin.com', 'facebook.com', 'twitter.com', 
    'instagram.com', 'netflix.com', 'paypal.com', 'office.com', 'live.com',
    'bing.com', 'yahoo.com', 'stackoverflow.com', 'wikipedia.org', 'dropbox.com',
    'chatgpt.com', 'openai.com'
}

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def analyze_url(url: str):
    """
    Performs a heuristic analysis of the given URL.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = tldextract.extract(url)
    domain = f"{parsed.domain}.{parsed.suffix}"
    
    findings = []
    warnings = []
    
    # 0. WHOIS Analysis
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            # Ensure creation_date is naive for subtraction with datetime.now()
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
                
            age_days = (datetime.now() - creation_date).days
            age_years = age_days // 365
            age_months = (age_days % 365) // 30
            
            findings.append(f"Domain Name: {domain}")
            findings.append(f"Age: ~{age_years} years, {age_months} months")
            findings.append(f"Registrar: {w.registrar if w.registrar else 'Unknown'}")
            
            if age_days < 180:
                warnings.append(f"Domain is very young (approx. {age_days} days). Phishing sites are often recently registered.")
        else:
            findings.append(f"Domain: {domain}")
            findings.append("Could not determine domain age (WHOIS data incomplete).")
    except Exception:
        findings.append(f"Domain: {domain}")
        # WHOIS failure is common for established sites due to rate-limiting; not necessarily a warning.
        findings.append("WHOIS data could not be retrieved. This occurs with some TLDs or protected domains.")

    # 1. Domain Analysis
    suspicious_tlds = ['xyz', 'top', 'pw', 'site', 'online', 'club', 'work']
    if parsed.suffix in suspicious_tlds:
        warnings.append(f"Unusual domain extension: .{parsed.suffix}")
    else:
        findings.append(f"Standard domain extension: .{parsed.suffix}")

    # Impersonation checks (simplified for demo)
    impersonations = {
        'amaz0n': 'amazon',
        'paypa1': 'paypal',
        'g00gle': 'google',
        'faceb00k': 'facebook'
    }
    for key, val in impersonations.items():
        if key in domain.lower():
            warnings.append(f"Possible brand impersonation detected: '{domain}' looks like '{val}'")

    # 2. Security Indicators
    is_https = url.startswith('https://')
    if is_https:
        findings.append("Secure connection (HTTPS) detected.")
    else:
        warnings.append("Connection is not secure (HTTP).")

    # 3. URL Structure
    if len(url) > 100:
        warnings.append("URL is unusually long, which can be a sign of hidden redirects.")
    
    random_strings = re.findall(r'[a-zA-Z0-9]{20,}', url)
    if random_strings:
        warnings.append("URL contains long random-looking character strings.")

    # 4. Phishing Signals (Keywords)
    suspicious_keywords = ['login', 'verify', 'account', 'security', 'update', 'banking', 'free', 'gift']
    # Check if keywords appear in the domain specifically (high risk)
    found_in_domain = [kw for kw in suspicious_keywords if kw in domain.lower()]
    found_in_path = [kw for kw in suspicious_keywords if kw in url.lower() and kw not in domain.lower()]
    
    if found_in_domain:
        warnings.append(f"High-risk keyword found in DOMAIN: {', '.join(found_in_domain)}")
    elif found_in_path:
        # Keywords in path are less suspicious for established sites
        findings.append(f"Common keyword in URL path: {', '.join(found_in_path)}")

    # Decision Logic
    is_trusted = domain in TRUSTED_DOMAINS
    
    risk_level = "Low"
    status = "REAL"
    confidence = 85
    advice = "SAFE TO USE"

    if is_trusted:
        status = "REAL"
        risk_level = "TRUSTED"
        confidence = 99
        advice = "OFFICIAL WEBSITE"
        findings.append(f"Verified official domain: {domain}")
    elif warnings:
        # Increase threshold for FAKE status
        if len(warnings) >= 3 or any("impersonation" in w for w in warnings):
            risk_level = "HIGH"
            status = "FAKE"
            advice = "DO NOT USE"
            confidence = 95
        else:
            risk_level = "MEDIUM"
            status = "SUSPICIOUS"
            advice = "VERIFY BEFORE USING"
            confidence = 70
    
    if "localhost:8000/test-phish" in url:
        return {
            "url": url,
            "status": "FAKE",
            "risk_level": "HIGH",
            "summary": "SYSTEM TEST: This local page is used to verify the Shield's automatic protection.",
            "findings": ["Localhost Test triggered"],
            "warnings": ["SYSTEM TEST: Phishing simulation active"],
            "advice": "DO NOT USE - SIMULATION",
            "confidence": 100
        }

    return {
        "url": url,
        "status": status,
        "risk_level": risk_level,
        "summary": "Legitimate websites use verified domains and secure connections. This URL was checked for structural anomalies and brand spoofing." if not warnings else "Multiple red flags were identified in the domain structure and security protocols.",
        "findings": findings,
        "warnings": warnings if warnings else ["None"],
        "advice": advice,
        "confidence": confidence
    }

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/test-phish", response_class=HTMLResponse)
async def test_phish(request: Request):
    return HTMLResponse(content="""
    <html>
        <head><title>Secure Login - Update Your Account</title></head>
        <body style='font-family: sans-serif; text-align: center; padding: 50px;'>
            <h1>⚠️ SECURITY ALERT</h1>
            <p>Please update your banking credentials immediately.</p>
            <form><input type='text' placeholder='Username'><br><br><input type='password' placeholder='Password'><br><br><button>Login</button></form>
        </body>
    </html>
    """)

@app.post("/analyze")
async def scan_url(url: str = Form(...)):
    report = analyze_url(url)
    return JSONResponse(content=report)

@app.get("/test-phish-preview", response_class=HTMLResponse)
async def test_phish_preview(request: Request):
    # This route simulates what the extension does: it injects the warning overlay
    return HTMLResponse(content="""
    <html>
        <head>
            <title>Secure Login - Update Your Account</title>
            <style>
                #guardlink-overlay {
                    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                    background: rgba(0, 0, 0, 0.9); z-index: 2147483647;
                    display: flex; justify-content: center; align-items: center;
                    font-family: sans-serif; color: white; backdrop-filter: blur(10px);
                }
                .warning-card {
                    background: #1a1a1a; border: 2px solid #ff4b2b;
                    padding: 3rem; border-radius: 20px; max-width: 500px;
                    text-align: center; box-shadow: 0 10px 50px rgba(0,0,0,0.5);
                }
                .gl-btn {
                    padding: 0.8rem 1.5rem; border-radius: 8px; cursor: pointer;
                    font-weight: 600; margin: 10px; transition: all 0.3s; border: none;
                }
                .gl-btn-primary { background: #ff4b2b; color: white; }
                .gl-btn-secondary { background: #333; color: #ccc; }
            </style>
        </head>
        <body style='font-family: sans-serif; text-align: center; padding: 50px;'>
            <div id="guardlink-overlay">
                <div class="warning-card">
                    <div style="font-size: 5rem; margin-bottom: 1rem;">⚠️</div>
                    <h1 style="color: #ff4b2b;">FAKE WEBSITE DETECTED</h1>
                    <p style="color: #ccc;">Our Shield has automatically blocked this suspicious page.</p>
                    <div style="background: #252525; padding: 1rem; border-radius: 10px; margin-bottom: 2rem; text-align: left;">
                        <p style="margin: 0; color: #888; font-size: 0.9rem;">REASON:</p>
                        <p style="margin: 5px 0 0 0; color: #eee;">Possible brand impersonation detected.</p>
                    </div>
                    <div>
                        <button class="gl-btn gl-btn-secondary">Proceed Anyway</button>
                        <button class="gl-btn gl-btn-primary">Leave Site Now</button>
                    </div>
                </div>
            </div>
            <h1>⚠️ SECURITY ALERT</h1>
            <p>Please update your banking credentials immediately.</p>
            <form><input type='text' placeholder='Username'><br/><br/><input type='password' placeholder='Password'><br/><br/><button>Login</button></form>
        </body>
    </html>
    """)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
