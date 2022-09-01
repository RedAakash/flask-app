import os
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir,'data.sqlite')
app.config['SECRET_KEY'] = 'super-secret-backend-creds'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECURITY_PASSWORD_SALT'] = b'$2b$12$wqKlYjmOfXPghx3FuC3Pu.'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class SupermecCreds(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    env_name = db.Column(db.String(255), unique=True)
    key = db.Column(db.String(255))
    value = db.Column(db.Text())

    def serialize(self, decrypt=False, input_password=None):
        data =  {
            'id': self.id,
            'env_name': self.env_name,
            'key': self.key,
            'value': self.value
        }

        if decrypt and input_password:
            data.update(
                verify = check_password_hash(self.value, input_password)
            )

        return data

    def __repr__(self):
        return f'{self.id}, {self.env_name}, {self.key}, {self.value}'

@app.route('/', methods=['GET'])
def get_all_objects():
    data = SupermecCreds.query.all()
    return {
        'status': 200,
        'data': [d.serialize() for d in data]
    }

@app.route('/get/<int:pk>/', methods=['GET'])
def get_by_pk(pk):
    data = SupermecCreds.query.filter_by(id=pk).first()
    return {
        'status': 200,
        'data': data.serialize()
    }

@app.route('/get-by-env-name/<env_name>/', methods=['GET'])
def get_by_env_name(env_name):
    data = SupermecCreds.query.filter_by(env_name=env_name).first()
    input_password = request.args.to_dict().get('password')

    return {
        'status': 200,
        'data': data.serialize(input_password = input_password, decrypt=True) if input_password else data.serialize()
    }

@app.route('/create', methods=['POST'])
def create_object():
    env_name = request.json.get('env_name')
    key = request.json.get('key')
    value = request.json.get('value')

    try:
        data = SupermecCreds(
            env_name = env_name,
            key = key,
            value = generate_password_hash(value)
        )

        db.session.add(data)
        db.session.commit()

        return {
            'error': False,
            'status': 200
        }

    except Exception as e:
        print(e)
        return {
            'error': True
        }

@app.route('/update/<int:pk>/', methods=['patch'])
def update_object(pk):
    data = SupermecCreds.query.filter_by(id=pk).first()

    data.env_name = request.json.get('env_name')
    data.key = request.json.get('key')
    data.value = generate_password_hash(request.json.get('value'))

    db.session.commit()

    return {
        'status': 200,
        'data': data.serialize(decrypt=True)
    }

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)