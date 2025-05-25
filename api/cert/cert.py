from flask import (
    Blueprint,
    request,
)
from api.extention import limiter, db
from api.utils import standard_response, server_sign
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from config import CA_CERTIFICATE, CA_PRIVATE_KEY, CLIENT_CERTIFICATE_TIMEOUT, TIME_WINDOW_SECOND
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
  - name: timeStamp
    in: formData
    type: integer
    required: true
  - name: userCSR
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

    try:
      timestamp = request.form.get('timeStamp', None)
      csr = x509.load_pem_x509_csr(
        request.form.get('userCSR').encode('utf-8'),
        default_backend())
    except:
      return standard_response(
        success=False,
        message='Lost some data',
        code=400
      )
    timestamp = int(timestamp)
    
    server_time = datetime.now(tz=timezone.utc).timestamp()
    if abs(server_time - timestamp) > TIME_WINDOW_SECOND:
      return standard_response(
        success=False,
        message='Request too old',
        code=403
      )
    
    if not csr.is_signature_valid:
      return standard_response(
        success=False,
        message='Invalid CSR signature',
        code=400
      )
    
    public_key = csr.public_key()
    subject = csr.subject

    key = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    username = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    
    user: Users = Users.query.filter_by(name=username).first()
    if(not user is None and user.user_public_key == key):
      if (int(timestamp) - user.last_query_time) < TIME_WINDOW_SECOND:
        return standard_response(
          success=False,
          message='Request too many times',
          code=403
        )
    
    serial_number = x509.random_serial_number()
    cert = server_sign(subject, public_key, serial_number)

    if user is None:
      data = Users(username, key, timestamp, serial_number)
      db.session.add(data)
      db.session.commit()
    else:
      user.update(public_key=key, time_stamp=timestamp, serial_number=serial_number)
      db.session.commit()
    
    return standard_response(
      data={
        'certificate': cert.public_bytes(serialization.Encoding.PEM).decode()
      }
    )