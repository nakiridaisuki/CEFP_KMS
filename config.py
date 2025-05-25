from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

DATABASE_URL = 'sqlite:///cefpkms.sqlite3'
CA_CERTIFICATE = x509.load_pem_x509_certificate(open('keys/ca.crt', 'rb').read(), default_backend())
CA_PRIVATE_KEY = serialization.load_pem_private_key(open('keys/ca.key', 'rb').read(), password=None)
CLIENT_CERTIFICATE_TIMEOUT = 365
TIME_WINDOW_SECOND = 300