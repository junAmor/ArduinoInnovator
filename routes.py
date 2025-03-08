from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, db
from models import User, Participant, Evaluation

# Dictionary to store all evaluator passwords, including new ones
evaluator_passwords = {
    'Jerome': 'jerome123',
    'Glen': 'glen123'
}

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
    return render_template('evaluators.html', evaluators=evaluators, default_passwords=evaluator_passwords)

@app.route('/evaluators/add', methods=['POST'])
@login_required
def add_evaluator():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please provide both username and password', 'danger')
        return redirect(url_for('evaluators'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('evaluators'))

    # Store the password in our dictionary before hashing
    evaluator_passwords[username] = password

    new_evaluator = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='evaluator'
    )
    db.session.add(new_evaluator)
    db.session.commit()

    flash('Evaluator added successfully', 'success')
    return redirect(url_for('evaluators'))

@app.route('/evaluators/delete/<int:evaluator_id>', methods=['POST'])
@login_required
def delete_evaluator(evaluator_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    evaluator = User.query.get_or_404(evaluator_id)
    if evaluator.role != 'evaluator':
        flash('Invalid evaluator', 'danger')
        return redirect(url_for('evaluators'))

    # Check if evaluator has any evaluations
    evaluations = Evaluation.query.filter_by(evaluator_id=evaluator_id).all()
    if evaluations:
        flash('Cannot delete evaluator with existing evaluations', 'danger')
        return redirect(url_for('evaluators'))

    # Remove the password from our dictionary
    if evaluator.username in evaluator_passwords:
        del evaluator_passwords[evaluator.username]

    db.session.delete(evaluator)
    db.session.commit()
    flash('Evaluator removed successfully', 'success')
    return redirect(url_for('evaluators'))

@app.route('/participants')
@login_required
def participants():
    participants = Participant.query.all()
    return render_template('participants.html', participants=participants)

@app.route('/participants/add', methods=['POST'])
@login_required
def add_participant():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    name = request.form.get('name')
    project_title = request.form.get('project_title')

    if not name or not project_title:
        flash('Please provide both group name and project title', 'danger')
        return redirect(url_for('participants'))

    new_participant = Participant(
        name=name,
        project_title=project_title
    )
    db.session.add(new_participant)
    db.session.commit()

    flash('Group added successfully', 'success')
    return redirect(url_for('participants'))

@app.route('/participants/delete/<int:participant_id>', methods=['POST'])
@login_required
def delete_participant(participant_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    participant = Participant.query.get_or_404(participant_id)

    # Check if participant has any evaluations
    evaluations = Evaluation.query.filter_by(participant_id=participant_id).all()
    if evaluations:
        flash('Cannot delete group with existing evaluations', 'danger')
        return redirect(url_for('participants'))

    db.session.delete(participant)
    db.session.commit()
    flash('Group removed successfully', 'success')
    return redirect(url_for('participants'))