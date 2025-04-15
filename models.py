from app import db
from datetime import datetime

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    target = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(32), default='queued')  # queued, running, completed, failed, cancelled
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    report_path = db.Column(db.String(512), nullable=True)
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target}>'
    
    def duration(self):
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return None
    
    def is_active(self):
        return self.status in ['queued', 'running']
