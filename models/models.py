from api.extention import db

relations = db.Table(
    'relations',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('key_id', db.Integer, db.ForeignKey('keys.id')),
)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    user_public_key = db.Column(db.String(80), unique=True, nullable=False)
    last_query_time = db.Column(db.Integer, nullable=False)
    serial_number = db.Column(db.String(80), nullable=False)

    def __init__(self, name, public_key, time_stamp, serial_number):
        self.name = name
        self.user_public_key = public_key
        self.last_query_time = time_stamp
        self.serial_number = str(serial_number)

    def update(self, public_key=None, time_stamp=None, serial_number=None):
        if not public_key is None:
            self.user_public_key = public_key
        if not time_stamp is None:
            self.last_query_time = time_stamp
        if not serial_number is None:
            self.serial_number = str(serial_number)


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