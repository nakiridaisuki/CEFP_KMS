from flask import Flask
from flask_cors import CORS
from config import DATABASE_URL
from models import Users, Keys

def create_app(mode: str = None) -> Flask:
    app = Flask(__name__)

    CORS(app)

    from api.extention import db
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    app.app_context().push()
    db.create_all()

    if mode is None:
        from api.extention import limiter
        limiter.init_app(app)


    from .cert.cert import gencert_api
    app.register_blueprint(gencert_api)

    from .key.distribukey import distribukey_api
    app.register_blueprint(distribukey_api)

    return app