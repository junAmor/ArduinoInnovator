import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager 
from sqlalchemy.orm import DeclarativeBase 

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configure PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    import models
    import routes
    db.create_all()

    # Create default admin and evaluator accounts if they don't exist
    from models import User
    from werkzeug.security import generate_password_hash

if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)

    evaluators = [
        {'username': 'Jerome', 'password': 'jerome123'},
        {'username': 'Glen', 'password': 'glen123'}
    ]


    for evaluator in evaluators:
        if not User.query.filter_by(username=evaluator['username']).first():
            new_evaluator = User(
                username=evaluator['username'],
                password_hash=generate_password_hash(evaluator['password']),
                role='evaluator'
            )
            db.session.add(new_evaluator)

    db.session.commit()
