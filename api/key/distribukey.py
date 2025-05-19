from flask import (
    Blueprint,
    request,
)
from api.extention import limiter, db
from api.utils import standard_response
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

@distribukey_api.route('/api/key/distributeKey/', methods=['POST'])
@limiter.limit('10 per minute')
def distribukey():
  """
  Get private or public key
  ---
  tags:
      - Generate Key
  produces: application/json
  parameters:
  - name: keyType
    in: formData
    type: string
    enum: [public, private]
    required: true
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
      description: Return the key
    400:
      description: Lose some data
  """
  if request.method == 'POST':

    certificate = request.form.get('certificate', None)
    allowed_users = list(set(request.form.get('allowedUsers', None).split(',')))
    type = request.form.get('keyType', None)
    if certificate is None or type is None:
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
    
  users = [x for x in allowed_users if not Users.query.filter_by(name=x).first() is None]
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

    if type == 'public':
      key = data.public_key
    elif type == 'private':
      key = data.private_key

    return standard_response(
      message='Generated a new key',
      data={
        'keyID': data.id,
        'key': key
      }
    )
  
  if type == 'public':
    key = result.public_key
  elif type == 'private':
    key = result.private_key
    
  return standard_response(
    message='key already exist',
    data={
      'keyID': result.id,
      'key': key
    }
  )
    