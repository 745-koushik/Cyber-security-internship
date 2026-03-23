from flask import Flask, request, jsonify, send_from_directory
import ssl
import socket
import datetime

app = Flask(__name__)

@app.route("/")
def home():
    return send_from_directory(".", "index.html")

def check_ssl(domain):
    result = {}
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()
                tls_version = ssock.version()

                result["TLS Version"] = tls_version

                expire_date = datetime.datetime.strptime(
                    cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
                )

                if expire_date < datetime.datetime.utcnow():
                    result["Certificate"] = "Expired"
                else:
                    result["Certificate"] = "Valid"

                if tls_version in ["TLSv1", "TLSv1.1"]:
                    result["Cipher Risk"] = "Weak TLS Version"
                else:
                    result["Cipher Risk"] = "Strong Encryption"

    except:
        result["Error"] = "Connection failed or possible MITM risk"

    return result


@app.route("/scan", methods=["POST"])
def scan():
    domain = request.json.get("domain")
    return jsonify(check_ssl(domain))


if __name__ == "__main__":
    app.run(debug=True)