from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import tldextract
import re
import requests
from datetime import datetime
import uvicorn

# Trusted high-reputation domains to avoid false positives
TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'microsoft.com', 'apple.com', 'github.com', 
    'amazon.com', 'amazon.in', 'linkedin.com', 'facebook.com', 'twitter.com', 
    'instagram.com', 'netflix.com', 'paypal.com', 'office.com', 'live.com',
    'bing.com', 'yahoo.com', 'stackoverflow.com', 'wikipedia.org', 'dropbox.com',
    'chatgpt.com', 'openai.com', 'cloudflare.com', 'railway.app'
}

app = FastAPI()

# Enable CORS for the Browser Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_domain_age_rdap(domain: str):
    """
    Fetches domain registration date using the modern RDAP protocol.
    Works on Cloudflare/Netlify/Render because it uses HTTP (Port 443).
    """
    try:
        # RDAP is the modern RESTful WHOIS
        response = requests.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"}, timeout=10)
        if response.status_code != 200:
            return None, "RDAP service unavailable or domain not found."
        
        data = response.json()
        events = data.get("events", [])
        
        # Look for the registration event
        reg_date_str = None
        for event in events:
            if event.get("eventAction") == "registration":
                reg_date_str = event.get("eventDate")
                break
        
        if not reg_date_str:
            return None, "Registration date not found in RDAP record."
            
        # Parse ISO date (e.g., 2020-03-24T12:00:00Z)
        # Remove the 'Z' and just take the date part
        date_part = reg_date_str.split('T')[0]
        reg_date = datetime.strptime(date_part, "%Y-%m-%d")
        
        age_days = (datetime.now() - reg_date).days
        return age_days, f"Domain established: {reg_date.strftime('%B %Y')}"
    except Exception as e:
        return None, f"RDAP Check Error: {str(e)}"

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
    
    # 1. Domain Age Check (using RDAP for Cloud Compatibility)
    age_days, age_msg = get_domain_age_rdap(domain)
    findings.append(f"Domain: {domain}")
    findings.append(age_msg)
    
    if age_days is not None and age_days < 180:
        warnings.append(f"Domain is very young (approx. {age_days} days). Phishing sites are often recently registered.")

    # 2. Domain TLD Analysis
    suspicious_tlds = ['xyz', 'top', 'pw', 'site', 'online', 'club', 'work']
    if parsed.suffix in suspicious_tlds:
        warnings.append(f"Unusual domain extension: .{parsed.suffix}")
    else:
        findings.append(f"Standard domain extension: .{parsed.suffix}")

    # 3. Impersonation Check (Simulated)
    impersonations = {
        'amaz0n': 'amazon',
        'paypa1': 'paypal',
        'g00gle': 'google',
        'faceb00k': 'facebook'
    }
    for key, val in impersonations.items():
        if key in domain.lower():
            warnings.append(f"Possible brand impersonation detected: '{domain}' looks like '{val}'")

    # 4. Security Indicators (HTTPS)
    is_https = url.startswith('https://')
    if is_https:
        findings.append("Secure connection (HTTPS) detected.")
    else:
        warnings.append("Connection is not secure (HTTP).")

    # 5. URL Structure Anomalies
    if len(url) > 100:
        warnings.append("URL is unusually long, which can hide redirects.")
    
    random_strings = re.findall(r'[a-zA-Z0-9]{20,}', url)
    if random_strings:
        warnings.append("URL contains long random character strings.")

    # 6. Phishing Signal Keywords
    suspicious_keywords = ['login', 'verify', 'account', 'security', 'update', 'banking', 'free', 'gift']
    found_in_domain = [kw for kw in suspicious_keywords if kw in domain.lower()]
    found_in_path = [kw for kw in suspicious_keywords if kw in url.lower() and kw not in domain.lower()]
    
    if found_in_domain:
        warnings.append(f"High-risk keyword found in DOMAIN: {', '.join(found_in_domain)}")
    elif found_in_path:
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
        if len(warnings) >= 3 or any("impersonation" in w for w in warnings):
            risk_level = "HIGH"
            status = "FAKE"
            advice = "DO NOT USE - MALICIOUS"
            confidence = 95
        else:
            risk_level = "MEDIUM"
            status = "SUSPICIOUS"
            advice = "VERIFY BEFORE PROCEEDING"
            confidence = 70

    return {
        "url": url,
        "status": status,
        "risk_level": risk_level,
        "summary": "Legitimate websites use verified domains and secure connections." if not warnings else "Multiple red flags were identified in the domain structure and security protocols.",
        "findings": findings,
        "warnings": warnings if warnings else ["None"],
        "advice": advice,
        "confidence": confidence
    }

@app.get("/")
async def root():
    return {"status": "online", "message": "GuardLink Scanner API is running!"}

@app.post("/analyze")
async def scan_url(url: str = Form(...)):
    report = analyze_url(url)
    return JSONResponse(content=report)

if __name__ == "__main__":
    # Detect $PORT for Cloud Deployment
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
