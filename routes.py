from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from app import app, db
from models import User, Participant, Evaluation

@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('leaderboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('leaderboard'))
        flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    participants = Participant.query.order_by(Participant.score.desc()).all()
    return render_template('leaderboard.html', participants=participants)

@app.route('/evaluators')
@login_required
def evaluators():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))
    evaluators = User.query.filter_by(role='evaluator').all()
    return render_template('evaluators.html', evaluators=evaluators)

@app.route('/participants')
@login_required
def participants():
    participants = Participant.query.all()
    return render_template('participants.html', participants=participants)