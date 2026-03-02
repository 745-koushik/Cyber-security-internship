import requests
import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Validate URL format
def is_valid_url(url):
    regex = re.compile(r'^(?:http|https)://(?:[\w-]+\.)+[a-zA-Z]{2,3}(?:/[^/\s]*)?$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Check SQL Injection
def check_sql_injection(url):
    if not is_valid_url(url):
        return "Invalid URL"
    
    payload = "' OR '1'='1"
    if '?' in url:
        test_url = url + "&id=" + payload
    else:
        test_url = url + "?id=" + payload

    try:
        response = requests.get(test_url, timeout=5)
        if "error" in response.text.lower() or response.status_code != 200:
            return f"Potential SQL Injection detected! Status Code: {response.status_code}"
        else:
            return f"No SQL Injection detected. Status Code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# Check XSS
def check_xss(url):
    if not is_valid_url(url):
        return "Invalid URL"
    
    payload = "<script>alert('XSS')</script>"
    if '?' in url:
        test_url = url + "&search=" + payload
    else:
        test_url = url + "?search=" + payload
    
    try:
        response = requests.get(test_url, timeout=5)
        if payload in response.text:
            return "Potential XSS vulnerability detected!"
        else:
            return "No XSS vulnerability detected."
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

# Check CSRF
def check_csrf(url):
    response = requests.get(url)
    if '<input type="hidden"' in response.text and 'csrf_token' in response.text:
        return "CSRF protection seems to be in place."
    else:
        return "No CSRF token found in the form."

# Check for security headers
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    missing_headers = []
    if 'Strict-Transport-Security' not in headers:
        missing_headers.append("Strict-Transport-Security")
    if 'X-Content-Type-Options' not in headers:
        missing_headers.append("X-Content-Type-Options")
    if 'X-Frame-Options' not in headers:
        missing_headers.append("X-Frame-Options")
    if 'Content-Security-Policy' not in headers:
        missing_headers.append("Content-Security-Policy")
    if missing_headers:
        return f"Missing security headers: {', '.join(missing_headers)}"
    return "All recommended security headers are present."

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    
    if not url:
        return jsonify({"message": "Error: No URL provided"}), 400
    
    if not is_valid_url(url):
        return jsonify({"message": "Invalid URL format"}), 400

    # Run the vulnerability scan
    sql_injection_result = check_sql_injection(url)
    xss_result = check_xss(url)
    csrf_result = check_csrf(url)
    headers_result = check_security_headers(url)

    return jsonify({
        "SQL Injection": sql_injection_result,
        "XSS": xss_result,
        "CSRF": csrf_result,
        "Security Headers": headers_result
    })

if __name__ == '__main__':
    app.run(debug=True)
