from flask import (
    Blueprint,
    request,
)
from api.extention import limiter, db
from api.utils import standard_response, server_sign
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from config import CA_CERTIFICATE
from models import Users, Keys
from sqlalchemy import func

distribukey_api = Blueprint('distribukey', __name__)

def generateKey() -> Keys:
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
  )
  public_key = private_key.public_key()
  
  priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
  ).decode()
  
  pub_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  ).decode()

  return Keys(
    private_key=priv_pem,
    public_key=pub_pem,
  )

@distribukey_api.route('/api/key/public/', methods=['POST'])
@limiter.limit('10 per minute')
def getPublicKey():
  """
  Get public key with allowed users
  ---
  tags:
      - Generate Key
  produces: application/json
  parameters:
  - name: allowedUsers
    in: formData
    type: array
    items:
      type: string
    required: true
  - name: certificate
    in: formData
    type: string
    required: true
  responses:
    200:
      description: Return the key and new certificate
    400:
      description: Lose some data
  """
  certificate = request.form.get('certificate', None)
  allowed_users = list(set(request.form.get('allowedUsers', None).split(',')))
  if certificate is None:
    return standard_response(
      success=False,
      message='Lose some data',
      code=400
    )
  
  cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'), default_backend())
  try:
    cert.verify_directly_issued_by(CA_CERTIFICATE)
  except Exception as e:
    return standard_response(
      success=False,
      message=e,
      code=401
    )

  cert_owner = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
  cert_user: Users = Users.query.filter_by(name=cert_owner).first()
  if(int(cert_user.serial_number) != cert.serial_number):
    return standard_response(
      success=False,
      message='Error certificate serial number',
      code=401
    )
    
  users = [x for x in allowed_users if not Users.query.filter_by(name=x).first() is None]
  if not cert_owner in users:
    return standard_response(
      success=False,
      message='Error certificate owner',
      code=401
    )
  
  subject = cert.subject
  public_key = cert.public_key()
  serial_number = x509.random_serial_number()
  new_cert = server_sign(subject, public_key, serial_number)

  key = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
  cert_user.update(public_key=key, serial_number=serial_number)
  db.session.commit()

  result = Keys.query.join(Keys.users) \
                      .filter(Users.name.in_(users)) \
                      .group_by(Keys.id) \
                      .having(func.count(Users.id.distinct()) == len(users)) \
                      .filter(~Keys.users.any(Users.name.notin_(users))) \
                      .first()

  if result is None:
    data = generateKey()
    data.users = Users.query.filter(Users.name.in_(users)).all()
    db.session.add(data)
    db.session.commit()

    return standard_response(
      message='Generated a new key',
      data={
        'keyID': data.id,
        'key': data.public_key,
        'certificate': new_cert.public_bytes(serialization.Encoding.PEM).decode()
      }
    )
    
  return standard_response(
    message='key already exist',
    data={
      'keyID': result.id,
      'key': result.public_key,
      'certificate': new_cert.public_bytes(serialization.Encoding.PEM).decode()
    }
  )
    
@distribukey_api.route('/api/key/private/', methods=['POST'])
@limiter.limit('10 per minute')
def getPrivateKey():
  """
  Get private key with key's Id
  ---
  tags:
      - Generate Key
  produces: application/json
  parameters:
  - name: KeyId
    in: formData
    type: array
    items:
      type: integer
    required: true
  - name: certificate
    in: formData
    type: string
    required: true
  responses:
    200:
      description: Return the key and new certificate
    400:
      description: Lose some data
  """
  certificate = request.form.get('certificate', None)
  keyID = request.form.get('keyId', None)
  if certificate is None or keyID is None:
    return standard_response(
      success=False,
      message='Lose some data',
      code=400
    )
  keyID = int(keyID)
  
  cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'), default_backend())
  try:
    cert.verify_directly_issued_by(CA_CERTIFICATE)
  except Exception as e:
    return standard_response(
      success=False,
      message=e,
      code=401
    )

  cert_owner = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
  cert_user: Users = Users.query.filter_by(name=cert_owner).first()
  if(int(cert_user.serial_number) != cert.serial_number):
    return standard_response(
      success=False,
      message='Error certificate serial number',
      code=401
    )
  
  subject = cert.subject
  public_key = cert.public_key()
  serial_number = x509.random_serial_number()
  new_cert = server_sign(subject, public_key, serial_number)

  key = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
  cert_user.update(public_key=key, serial_number=serial_number)
  db.session.commit()

  result = Keys.query.filter_by(id=keyID).first()

  if result is None:
    return standard_response(
      success=False,
      message='Error key id',
      code=400
    )
    
  return standard_response(
    message='key already exist',
    data={
      'key': result.private_key,
      'certificate': new_cert.public_bytes(serialization.Encoding.PEM).decode()
    }
  )
    