from flask import Flask, render_template, request
import re
import socket
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)


def check_url(url):
    score = 0
    reasons = []

    # Check URL length
    if len(url) > 75:
        score += 20
        reasons.append("URL is too long")

    # Check IP address
    if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
        score += 25
        reasons.append("IP address used instead of domain")

    # Check HTTPS
    if not url.startswith('https'):
        score += 15
        reasons.append("No HTTPS security")

    # Check suspicious keywords
    keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'paypal', 'signin']
    for k in keywords:
        if k in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {k}")
            break

    # Check @ symbol
    if '@' in url:
        score += 25
        reasons.append("@ symbol found in URL")

    # Check hyphens
    if url.count('-') > 3:
        score += 15
        reasons.append("Too many hyphens")

    # Check dots
    if url.count('.') > 4:
        score += 15
        reasons.append("Too many dots")

    # Check URL shortener
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']
    if any(s in url for s in shorteners):
        score += 20
        reasons.append("URL shortener detected")

    # Check suspicious Top-Level Domain (TLD)
    suspicious_tlds = ['.xyz', '.top', '.click', '.live', '.work']

    domain = urlparse(url).netloc.lower()

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 10
        reasons.append("Suspicious Top-Level Domain")

    # Check Domain Age
    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        # Sometimes WHOIS returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days

            if age_days < 180:
                score += 15
                reasons.append("Newly registered domain")

    except Exception:
        pass

    if score >= 40:
        result = "PHISHING"
        color = "red"
    else:
        result = "LEGITIMATE"
        color = "green"

    return result, score, reasons, color


def get_threat_report(url):
    """
    NEW FEATURE: Threat Intelligence Report
    Shows WHO created the site, WHEN it was created, and WHERE it is hosted.
    """
    report = {
        "status": "OFFLINE",
        "domain": "Unknown",
        "owner": "Unknown",
        "created_date": "Unknown",
        "expiry_date": "Unknown",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "ip_address": "Unknown"
    }

    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = urlparse("http://" + url).netloc or url
        report["domain"] = domain

      
        ip = socket.gethostbyname(domain)
        report["status"] = "LIVE"
        report["ip_address"] = ip

        geo = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        report["country"] = geo.get("country", "Unknown")
        report["city"] = geo.get("city", "Unknown")
        report["isp"] = geo.get("org", "Unknown")

        # WHOIS Information
        try:
            domain_info = whois.whois(domain)
            

            report["owner"] = domain_info.registrar or "Unknown"

            creation_date = domain_info.creation_date
            expiry_date = domain_info.expiration_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]

            report["created_date"] = creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown"
            report["expiry_date"] = expiry_date.strftime("%Y-%m-%d") if expiry_date else "Unknown"

        except Exception:
            pass
    except Exception as e:
        print(f"Threat report error: {e}")
    print(report)
    return report


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    score = None
    reasons = []
    color = None
    url = None
    threat_report = None  # NEW

    if request.method == 'POST':
        url = request.form['url']
        result, score, reasons, color = check_url(url)

        # NEW: get threat intelligence report
        threat_report = get_threat_report(url)

    return render_template('index.html',
                            result=result, score=score,
                            reasons=reasons, color=color, url=url,
                            threat_report=threat_report, bulk_results=[]
)  # NEW
@app.route('/bulk_scan', methods=['POST'])
def bulk_scan():
    urls = request.form.get('bulk_urls','').splitlines()

    bulk_results = []

    for url in urls[:100]:
        url = url.strip()
        if url:
            result, score, reasons, color = check_url(url)

            bulk_results.append({
                "url": url,
                "result": result,
                "score": score
            })

    return render_template(
        "index.html",
        bulk_results=bulk_results,
        result=None,
        score=None,
        reasons=[],
        color=None,
        url=None,
        threat_report=None
    )
@app.route('/bulk')
def bulk():
    return render_template("bulk.html")


if __name__ == '__main__':
    app.run(debug=True)