from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, db
from models import User, Participant, Evaluation
from sqlalchemy import and_

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
        if current_user.role == 'evaluator':
            return redirect(url_for('select_participant'))
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
            if user.role == 'evaluator':
                return redirect(url_for('select_participant'))
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
    participants = Participant.query.all()
    evaluators = User.query.filter_by(role='evaluator').all()
    
    # Check if all evaluations are complete
    all_evaluations_complete = True
    
    # Count total expected evaluations vs actual evaluations
    total_expected = len(participants) * len(evaluators)
    total_actual = Evaluation.query.count()
    
    if total_actual < total_expected:
        all_evaluations_complete = False
    
    # Calculate weighted scores if all evaluations are complete
    if all_evaluations_complete:
        for participant in participants:
            evaluations = Evaluation.query.filter_by(participant_id=participant.id).all()
            
            if evaluations:
                # Calculate average scores for each criterion
                participant.avg_project_design = sum(e.project_design for e in evaluations) / len(evaluations)
                participant.avg_functionality = sum(e.functionality for e in evaluations) / len(evaluations)
                participant.avg_presentation = sum(e.presentation for e in evaluations) / len(evaluations)
                participant.avg_web_design = sum(e.web_design for e in evaluations) / len(evaluations)
                participant.avg_impact = sum(e.impact for e in evaluations) / len(evaluations)
                
                # Calculate weighted final score using the provided formula
                # For the new 0-100 scale
                weighted_scores = []
                for evaluation in evaluations:
                    weighted_score = (
                        (evaluation.project_design * 0.25) +
                        (evaluation.functionality * 0.30) +
                        (evaluation.presentation * 0.15) +
                        (evaluation.web_design * 0.10) +
                        (evaluation.impact * 0.20)
                    )
                    weighted_scores.append(weighted_score)
                
                # Final score is the average of all evaluator weighted scores
                participant.score = sum(weighted_scores) / len(weighted_scores)
            else:
                participant.avg_project_design = 0
                participant.avg_functionality = 0
                participant.avg_presentation = 0
                participant.avg_web_design = 0
                participant.avg_impact = 0
                participant.score = 0
        
        # Sort participants by score after calculation
        participants = sorted(participants, key=lambda p: p.score, reverse=True)
    
    return render_template('leaderboard.html', participants=participants, 
                          all_evaluations_complete=all_evaluations_complete,
                          completed_evaluations=total_actual,
                          total_evaluations=total_expected)

@app.route('/evaluators')
@login_required
def evaluators():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    evaluators = User.query.filter_by(role='evaluator').all()
    
    # Get all evaluations for each evaluator
    evaluator_evaluations = {}
    for evaluator in evaluators:
        evaluations = Evaluation.query.filter_by(evaluator_id=evaluator.id).all()
        evaluator_evaluations[evaluator.id] = []
        
        for evaluation in evaluations:
            participant = Participant.query.get(evaluation.participant_id)
            evaluator_evaluations[evaluator.id].append({
                'evaluation': evaluation,
                'participant': participant
            })
    
    return render_template(
        'evaluators.html', 
        evaluators=evaluators, 
        default_passwords=evaluator_passwords,
        evaluator_evaluations=evaluator_evaluations
    )

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
        role='evaluator')
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

    group_number = request.form.get('group_number')
    name = request.form.get('name')
    project_title = request.form.get('project_title')

    if not group_number or not name or not project_title:
        flash('Please provide group number, group name, and project title', 'danger')
        return redirect(url_for('participants'))
        
    try:
        group_number = int(group_number)
    except ValueError:
        flash('Group number must be a valid integer', 'danger')
        return redirect(url_for('participants'))

    # Check if group number already exists
    if Participant.query.filter_by(group_number=group_number).first():
        flash('A group with this number already exists', 'danger')
        return redirect(url_for('participants'))

    new_participant = Participant(
        group_number=group_number,
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

@app.route('/participants/reset', methods=['POST'])
@login_required
def reset_participants():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))
    
    # Delete all evaluations first to avoid foreign key constraints
    Evaluation.query.delete()
    
    # Delete all participants
    Participant.query.delete()
    
    # Commit the changes
    db.session.commit()
    
    flash('All participants and evaluations have been reset', 'success')
    return redirect(url_for('participants'))

@app.route('/evaluations/reset', methods=['POST'])
@login_required
def reset_evaluations():
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))
    
    # Delete only the evaluations from the current evaluator
    Evaluation.query.filter_by(evaluator_id=current_user.id).delete()
    
    # Commit the changes
    db.session.commit()
    
    flash('All your evaluations have been reset. You can start evaluating again.', 'success')
    return redirect(url_for('select_participant'))

@app.route('/reset_all_data', methods=['POST'])
@login_required
def reset_all_data():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))
    
    # Delete all evaluations first to avoid foreign key constraints
    Evaluation.query.delete()
    
    # Reset scores for all participants
    for participant in Participant.query.all():
        participant.score = 0.0
    
    # Commit the changes
    db.session.commit()
    
    flash('All data has been reset. Evaluations deleted and scores reset to zero.', 'success')
    return redirect(url_for('leaderboard'))

@app.route('/select_participant')
@login_required
def select_participant():
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Get all participants
    all_participants = Participant.query.all()
    
    # Get IDs and evaluations of participants that have been evaluated by current evaluator
    evaluations = Evaluation.query.filter_by(evaluator_id=current_user.id).all()
    evaluated_participant_ids = [eval.participant_id for eval in evaluations]
    
    # Create a dictionary to store evaluation IDs for each participant
    evaluation_ids = {eval.participant_id: eval.id for eval in evaluations}

    return render_template(
        'select_participant.html', 
        all_participants=all_participants,
        evaluated_participant_ids=evaluated_participant_ids,
        evaluation_ids=evaluation_ids,
        show_leaderboard=False
    )

@app.route('/rate_participant/<int:participant_id>', methods=['GET', 'POST'])
@login_required
def rate_participant(participant_id):
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    participant = Participant.query.get_or_404(participant_id)

    # Check if already rated
    existing_evaluation = Evaluation.query.filter_by(
        evaluator_id=current_user.id,
        participant_id=participant_id
    ).first()
    
    if existing_evaluation:
        flash('You have already evaluated this participant. Please use the edit option.', 'warning')
        return redirect(url_for('select_participant'))

    if request.method == 'POST':
        try:
            # Validate that input values are between 1 and 100
            project_design = float(request.form['project_design'])
            functionality = float(request.form['functionality'])
            presentation = float(request.form['presentation'])
            web_design = float(request.form['web_design'])
            impact = float(request.form['impact'])
            
            # Ensure all scores are between 1 and 100
            if not all(1 <= score <= 100 for score in [project_design, functionality, presentation, web_design, impact]):
                flash('All scores must be between 1 and 100', 'danger')
                return render_template('rate_participant.html', participant=participant)
            
            evaluation = Evaluation(
                participant_id=participant_id,
                evaluator_id=current_user.id,
                project_design=project_design,
                functionality=functionality,
                presentation=presentation,
                web_design=web_design,
                impact=impact,
                comments=request.form.get('comments', '')
            )

            db.session.add(evaluation)
            db.session.commit()
            flash('Evaluation submitted successfully', 'success')

            return redirect(url_for('select_participant'))

        except (ValueError, KeyError):
            flash('Invalid evaluation data submitted', 'danger')
            return render_template('rate_participant.html', participant=participant)

    return render_template('rate_participant.html', participant=participant)

@app.route('/edit_evaluation/<int:evaluation_id>', methods=['GET', 'POST'])
@login_required
def edit_evaluation(evaluation_id):
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))
        
    # Get the evaluation
    evaluation = Evaluation.query.get_or_404(evaluation_id)
    
    # Check if the evaluation belongs to the current user
    if evaluation.evaluator_id != current_user.id:
        flash('You can only edit your own evaluations', 'danger')
        return redirect(url_for('select_participant'))
        
    participant = Participant.query.get_or_404(evaluation.participant_id)
    
    if request.method == 'POST':
        try:
            # Validate that input values are between 1 and 100
            project_design = float(request.form['project_design'])
            functionality = float(request.form['functionality'])
            presentation = float(request.form['presentation'])
            web_design = float(request.form['web_design'])
            impact = float(request.form['impact'])
            
            # Ensure all scores are between 1 and 100
            if not all(1 <= score <= 100 for score in [project_design, functionality, presentation, web_design, impact]):
                flash('All scores must be between 1 and 100', 'danger')
                return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant)
            
            # Update the evaluation
            evaluation.project_design = project_design
            evaluation.functionality = functionality
            evaluation.presentation = presentation
            evaluation.web_design = web_design
            evaluation.impact = impact
            evaluation.comments = request.form.get('comments', '')
            
            db.session.commit()
            flash('Evaluation updated successfully', 'success')
            return redirect(url_for('select_participant'))
            
        except (ValueError, KeyError):
            flash('Invalid evaluation data submitted', 'danger')
            return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant)
    
    return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant)


# Speed test routes removed