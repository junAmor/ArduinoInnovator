
from app import app, db
from models import User, Participant, Evaluation
import os

def update_participant_table():
    with app.app_context():
        # Check if column exists already
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('participant')]
        
        if 'group_number' not in columns:
            print("Adding group_number column to participant table...")
            # Add the column with a default value of 1
            db.session.execute(text('ALTER TABLE participant ADD COLUMN group_number INTEGER DEFAULT 1'))
            
            # Set each participant's group_number equal to their id to maintain existing ordering
            participants = Participant.query.all()
            for i, participant in enumerate(participants, 1):
                participant.group_number = i
            
            db.session.commit()
            print("Database updated successfully!")
        else:
            print("group_number column already exists.")

if __name__ == '__main__':
    update_participant_table()
