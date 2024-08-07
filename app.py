
from flask import Flask, request, jsonify
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

app = Flask(__name__)

def check_sql_injection(url):
    sql_payload = "' OR '1'='1"
    vulnerable = False
    try:
        response = requests.get(url + sql_payload)
        if "SQL" in response.text or "error" in response.text:
            vulnerable = True
    except Exception as e:
        print(f"Error checking SQL injection: {e}")
    return vulnerable

def check_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    vulnerable = False
    try:
        response = requests.get(url)
        if xss_payload in response.text:
            vulnerable = True
    except Exception as e:
        print(f"Error checking XSS: {e}")
    return vulnerable

def check_csrf(url):
    csrf_token = False
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all("form"):
            if form.find("input", {"name": "csrf_token"}) or form.find("input", {"name": "csrfmiddlewaretoken"}):
                csrf_token = True
                break
    except Exception as e:
        print(f"Error checking CSRF: {e}")
    return not csrf_token

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url

    sql_injection = check_sql_injection(url)
    xss = check_xss(url)
    csrf = check_csrf(url)

    return jsonify({
        "url": url,
        "vulnerabilities": {
            "sql_injection": sql_injection,
            "xss": xss,
            "csrf": csrf
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
