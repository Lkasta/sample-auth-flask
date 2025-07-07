import os
from dotenv import load_dotenv

from database import db
import bcrypt
from flask import Flask, jsonify, request
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

from models.user import User

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

@app.route('/register-user', methods=['POST'])
def register_user():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt()).decode()
    user = User(username=username, password=hashed_password, role='user')
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Created user"})

  return jsonify({"message": "Invalid credentials"}), 400

@app.route('/user/<int:user_id>', methods=['GET'])
def read_user(user_id):
  user = User.query.get(user_id)

  if user:
    return {"id": user.id, "username": user.username}
  
  return jsonify({"message": "User not found!"}), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
  if current_user.role != 'user':
    return jsonify({"message": "Unauthorized"}), 403
  
  data = request.json
  hash_password = data.get("password")
  user = User.query.get(user_id)

  if user and data.get("password"):
    user.password = bcrypt.hashpw(hash_password.encode(), bcrypt.gensalt()).decode()
    db.session.commit()

    return jsonify({"message": "User has been updated!"})

  return jsonify({"message": f"User id {user_id} not found"}), 400

@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
  user = User.query.get(user_id)

  if user:
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User has been deleted!"})
  
  return jsonify({"message": "User not found!"}), 404

@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.checkpw(password.encode(), user.password.encode()):
      login_user(user)
      print(f'UserId: {current_user.id}')
      return jsonify({"message": "Login"}) 

  return jsonify({"message": "Invalid credentials!"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
  logout_user()
  return jsonify({"message": "User logged out."})

@app.route("/", methods=['GET'])
def hello_jonas():
  return "Jonas" 

if __name__ == '__main__':
  app.run(debug=True)