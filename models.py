from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    project_title = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Float, default=0.0)
    evaluations = db.relationship('Evaluation', backref='participant', lazy=True)

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey('participant.id'), nullable=False)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_design = db.Column(db.Float, nullable=False)  # 25%
    functionality = db.Column(db.Float, nullable=False)   # 30%
    presentation = db.Column(db.Float, nullable=False)    # 15%
    web_design = db.Column(db.Float, nullable=False)      # 10%
    impact = db.Column(db.Float, nullable=False)          # 20%
    comments = db.Column(db.Text)

    @property
    def total_score(self):
        # Weighted score calculation as explained in the requirements
        # Project Design (25%) + Functionality (30%) + Presentation (15%) + Web Design (10%) + Impact (20%)
        return (
            self.project_design * 0.25 +
            self.functionality * 0.30 +
            self.presentation * 0.15 +
            self.web_design * 0.10 +
            self.impact * 0.20
        )