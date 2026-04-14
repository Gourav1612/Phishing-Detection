from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    prediction = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    host_info = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'prediction': self.prediction,
            'confidence': self.confidence,
            'risk_level': self.rik_level,
            'ip_address': self.ip_address,
            'host_info': self.host_info,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
