from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    dest_ip = db.Column(db.String(50))
    protocol = db.Column(db.String(20))
    length = db.Column(db.Integer)
    info = db.Column(db.Text)
    severity = db.Column(db.String(20), default='low')
    is_threat = db.Column(db.Boolean, default=False)
    ai_summary = db.Column(db.Text, default='')
    dest_port = db.Column(db.String(10), default='0')
    threat_summary = db.Column(db.Text, default='Clean')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'protocol': self.protocol,
            'length': self.length,
            'info': self.info,
            'severity': self.severity,
            'is_threat': self.is_threat,
            'ai_summary': self.ai_summary,
            'dest_port': self.dest_port,
            'threat_summary': self.threat_summary
        }
