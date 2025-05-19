from api.extention import db

relations = db.Table(
    'relations',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('key_id', db.Integer, db.ForeignKey('keys.id')),
)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __init__(self, name):
        self.name = name

class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

    users = db.relationship(
        'Users',
        secondary=relations,
        backref=db.backref('key')
    )

    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key