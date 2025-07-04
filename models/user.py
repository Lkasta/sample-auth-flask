from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Colunm(db.String(80), nullable=False, unique=True)
  password = db.Column(db.string(80), nullable=False)

