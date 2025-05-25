from flask import jsonify
from typing import Dict
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import CA_CERTIFICATE, CLIENT_CERTIFICATE_TIMEOUT, CA_PRIVATE_KEY
from datetime import datetime, timedelta

def standard_response(success=True, data=None, message="", code=200):
    if isinstance(data, Dict):
        keys = data.keys()
        if('hashed_password' in keys):
            del data['hashed_password']
        if('salt' in keys):
            del data['salt']

    return jsonify({
        "success": success,
        "data": data,
        "message": message
    }), code

def server_sign(subject, public_key, serial_number):
    cert = x509.CertificateBuilder().subject_name(
      subject
    ).issuer_name(
      CA_CERTIFICATE.subject
    ).public_key(
      public_key
    ).serial_number(
      serial_number
    ).not_valid_before(
      datetime.utcnow()
    ).not_valid_after(
      datetime.utcnow() + timedelta(days=CLIENT_CERTIFICATE_TIMEOUT)
    ).sign(CA_PRIVATE_KEY, hashes.SHA256(), default_backend())
    return cert