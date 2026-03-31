import whois
from datetime import datetime

def test_whois(domain):
    print(f"Analyzing: {domain}")
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.now() - creation_date).days
            print(f"  Age: {age_days} days")
            print(f"  Registrar: {w.registrar}")
        else:
            print("  Creation date not found")
    except Exception as e:
        print(f"  Error: {e}")

if __name__ == "__main__":
    test_whois("google.com")
    test_whois("microsoft.com")
    test_whois("suspicious-test.xyz")