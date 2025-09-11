import re
import tldextract
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import urllib.parse
import socket


def extract_url_features(url):
    """
    Extract features from a URL based on phishing dataset columns.
    Each feature returns: 1 (phishing/negative), -1 (legit/positive), 0 (suspicious/unknown).
    """
    features = {}

    # Parse URL
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Extract domain parts
    ext = tldextract.extract(url)

    # 1. having_IP_Address
    features['having_IP_Address'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else -1

    # 2. URL_Length
    length = len(url)
    features['URL_Length'] = 1 if length >= 75 else (-1 if length < 54 else 0)

    # 3. Shortining_Service
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    features['Shortining_Service'] = 1 if any(s in domain for s in shorteners) else -1

    # 4. having_At_Symbol
    features['having_At_Symbol'] = 1 if '@' in url else -1

    # 5. double_slash_redirecting
    features['double_slash_redirecting'] = 1 if '//' in path else -1

    # 6. Prefix_Suffix
    features['Prefix_Suffix'] = 1 if '-' in ext.domain else -1

    # 7. having_Sub_Domain
    subdomain_count = len([x for x in ext.subdomain.split('.') if x]) if ext.subdomain else 0
    features['having_Sub_Domain'] = 1 if subdomain_count > 1 else (-1 if subdomain_count == 0 else 0)

    # 8. SSLfinal_State
    features['SSLfinal_State'] = 1 if parsed_url.scheme == 'https' else -1

    # 9. Domain_registeration_length
    try:
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        features['Domain_registeration_length'] = -1 if exp_date and (exp_date - datetime.now()).days > 365 else 1
    except:
        features['Domain_registeration_length'] = 0

    # 10. Favicon
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if favicon and domain in favicon.get("href", ""):
            features['Favicon'] = -1
        else:
            features['Favicon'] = 1
    except:
        features['Favicon'] = 0

    # 11. port
    features['port'] = 1 if ':' in domain and not domain.endswith((":80", ":443")) else -1

    # 12. HTTPS_token
    features['HTTPS_token'] = 1 if 'https' in domain.lower() else -1

    # 13. Request_URL
    features['Request_URL'] = 1 if query else -1

    # 14. URL_of_Anchor
    try:
        anchors = soup.find_all('a', href=True)
        total = len(anchors)
        unsafe = len([a for a in anchors if '#' in a['href'] or 'javascript' in a['href'].lower()])
        ratio = unsafe / total if total > 0 else 0
        features['URL_of_Anchor'] = 1 if ratio > 0.67 else (-1 if ratio < 0.31 else 0)
    except:
        features['URL_of_Anchor'] = 0

    # 15. Links_in_tags
    try:
        metas = soup.find_all('meta')
        links = soup.find_all('link')
        scripts = soup.find_all('script')
        total = len(metas) + len(links) + len(scripts)
        external = len([l for l in links if domain not in l.get('href', '')])
        ratio = external / total if total > 0 else 0
        features['Links_in_tags'] = 1 if ratio > 0.67 else (-1 if ratio < 0.31 else 0)
    except:
        features['Links_in_tags'] = 0

    # 16. SFH (Server Form Handler)
    try:
        forms = soup.find_all('form', action=True)
        if not forms:
            features['SFH'] = -1
        else:
            bad = [f for f in forms if f['action'] in ["", "about:blank"] or domain not in f['action']]
            features['SFH'] = 1 if bad else -1
    except:
        features['SFH'] = 0

    # 17. Submitting_to_email
    features['Submitting_to_email'] = 1 if 'mailto:' in url.lower() else -1

    # 18. Abnormal_URL
    features['Abnormal_URL'] = 1 if not domain or not ext.suffix else -1

    # 19. Redirect
    redirect_keywords = ['redirect', 'url=', 'goto=', 'return=', 'next=']
    features['Redirect'] = 1 if any(k in query.lower() for k in redirect_keywords) else -1

    # 20. on_mouseover
    try:
        if "onmouseover" in r.text.lower():
            features['on_mouseover'] = 1
        else:
            features['on_mouseover'] = -1
    except:
        features['on_mouseover'] = 0

    # 21. RightClick
    try:
        if "event.button==2" in r.text.lower() or "contextmenu" in r.text.lower():
            features['RightClick'] = 1
        else:
            features['RightClick'] = -1
    except:
        features['RightClick'] = 0

    # 22. popUpWidnow
    features['popUpWidnow'] = 1 if "popup" in url.lower() else -1

    # 23. Iframe
    try:
        features['Iframe'] = 1 if "<iframe" in r.text.lower() else -1
    except:
        features['Iframe'] = 0

    # 24. age_of_domain
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.now() - creation).days if creation else 0
        features['age_of_domain'] = -1 if age_days > 180 else 1
    except:
        features['age_of_domain'] = 0

    # 25. DNSRecord
    try:
        socket.gethostbyname(domain)
        features['DNSRecord'] = -1
    except:
        features['DNSRecord'] = 1

    # 26. web_traffic (placeholder using Alexa API — retired)
    features['web_traffic'] = 0

    # 27. Page_Rank (placeholder)
    features['Page_Rank'] = 0

    # 28. Google_Index
    try:
        google = requests.get(f"https://www.google.com/search?q=site:{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        features['Google_Index'] = -1 if "did not match any documents" in google.text else 1
    except:
        features['Google_Index'] = 0

    # 29. Links_pointing_to_page
    try:
        backlinks = len(soup.find_all('a'))
        features['Links_pointing_to_page'] = -1 if backlinks > 2 else 1
    except:
        features['Links_pointing_to_page'] = 0

    # 30. Statistical_report (placeholder — requires blacklist database)
    blacklist_keywords = ["phishing", "malware", "blacklist"]
    features['Statistical_report'] = 1 if any(k in url.lower() for k in blacklist_keywords) else -1

    return features
