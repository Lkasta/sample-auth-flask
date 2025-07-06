from flask import Flask, jsonify, request
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"

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
    user = User(username=username, password=password)
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
  data = request.json
  user = User.query.get(user_id)

  if current_user.id != user_id:
    return jsonify({"message": "Unauthorized"}), 403

  if user and data.get("password"):
    user.password = data.get("password")
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
    if user and user.password == password:
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