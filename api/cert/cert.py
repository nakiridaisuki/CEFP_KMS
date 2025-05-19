from flask import (
    Blueprint,
    request,
)
from api.extention import limiter, db
from api.utils import standard_response
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from config import CA_CERTIFICATE, CA_PRIVATE_KEY, CLIENT_CERTIFICATE_TIMEOUT
from models import Users

gencert_api = Blueprint('cert', __name__)

@gencert_api.route('/api/cert/gencert', methods=['POST'])
@limiter.limit('10 pre minut')
def gencert():
  """
  Gererage a certificate for user
  ---
  tags:
      - Generate Certificate
  produces: application/json
  parameters:
  - name: username
    in: formData
    type: string
    required: true
  - name: public_key
    in: formData
    type: string
    required: true
  responses:
    200:
      description: Return a certificate
    400:
      description: Lose some data
  """
  if request.method == 'POST':

    username = request.form.get('username', None)
    if username is None:
      return standard_response(
        success=False,
        message='No username',
        code=400
      )
    
    try:
      client_public_key = serialization.load_pem_public_key(
        request.form.get('publicKey', None).encode('utf-8'),
        backend=default_backend()
      )
    except:
      return standard_response(
        success=False,
        message='Lose public key or in wrong format',
        code=400
      )

    subject = x509.Name([
      x509.NameAttribute(NameOID.COMMON_NAME, username)
    ])
    
    cert = x509.CertificateBuilder().subject_name(
      subject
    ).issuer_name(
      CA_CERTIFICATE.subject
    ).public_key(
      client_public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      datetime.utcnow()
    ).not_valid_after(
      datetime.utcnow() + timedelta(days=CLIENT_CERTIFICATE_TIMEOUT)
    ).sign(CA_PRIVATE_KEY, hashes.SHA256(), default_backend())

    user: Users = Users.query.filter_by(name=username).first()
    if user is None:
      data = Users(username)
      db.session.add(data)
      db.session.commit()
    
    return standard_response(
      data={
        'certificate': cert.public_bytes(serialization.Encoding.PEM).decode()
      }
    )