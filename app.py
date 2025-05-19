from api import create_app
from flasgger import Swagger

app = create_app('app')
app.config['SWAGGER'] = {
    "title": "KMS API",
    "description": "KMS API",
    "version": "0.0.1",
    "termsOfService": "",
    "hide_top_bar": True,
}
Swagger(app)

from api.extention import db
@app.route('/')
def index():
    db.create_all()
    return 'ok'

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.2')