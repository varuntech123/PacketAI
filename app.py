import os
import subprocess
import requests
from flask import Flask, render_template, jsonify, request
from werkzeug.utils import secure_filename
from sqlalchemy import text

# Internal PacketAI Components
from models import db, SecurityEvent
from threat_detection import detect_threat
from ai_analyzer import analyze_event, analyze_full_pcap, analyze_chat

app = Flask(__name__)

# Ensure instance folder exists for SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "events.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Initialize DB with App
db.init_app(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Cache for IP enrichment
ip_cache = {}

def parse_pcap(filepath):
    """Deep PCAP Parser using tshark engine."""
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    cmd = [
        tshark_path, "-r", filepath,
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-e", "tcp.dstport",
        "-e", "udp.dstport"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        
        with app.app_context():
            # Session Reset for new analysis
            db.session.execute(text("DELETE FROM security_event"))
            db.session.commit()
            
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 6:
                    port = parts[6] if len(parts) > 6 and parts[6] else (parts[7] if len(parts) > 7 and parts[7] else "0")
                    is_t, sev, summ = detect_threat(parts[1], parts[2], parts[4], int(parts[3]) if parts[3].isdigit() else 0, parts[5])
                    
                    event = SecurityEvent(
                        timestamp=parts[0],
                        source_ip=parts[1],
                        dest_ip=parts[2],
                        length=int(parts[3]) if parts[3].isdigit() else 0,
                        protocol=parts[4],
                        info=parts[5],
                        dest_port=port,
                        is_threat=is_t,
                        severity=sev,
                        threat_summary=summ
                    )
                    db.session.add(event)
            db.session.commit()
        return True
    except Exception as e:
        print(f"Extraction Error: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        if parse_pcap(filepath):
            return jsonify({'success': True, 'message': 'Packet session initialized'})
        return jsonify({'error': 'Parsing failed'}), 500

@app.route('/api/events', methods=['GET'])
def get_events():
    limit = request.args.get('limit', 10000, type=int)
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in events])

@app.route('/api/stats')
def get_stats():
    """Industrial SIEM statistical aggregation."""
    try:
        total_packets = SecurityEvent.query.count()
        protocols = db.session.query(SecurityEvent.protocol, db.func.count(SecurityEvent.id)).group_by(SecurityEvent.protocol).all()
        top_talkers = db.session.query(SecurityEvent.source_ip, SecurityEvent.dest_ip, db.func.count(SecurityEvent.id).label('count')).group_by(SecurityEvent.source_ip, SecurityEvent.dest_ip).order_by(db.desc('count')).limit(10).all()
        top_ports = db.session.query(SecurityEvent.dest_port, db.func.count(SecurityEvent.id).label('count')).filter(SecurityEvent.dest_port != "0").group_by(SecurityEvent.dest_port).order_by(db.desc('count')).limit(5).all()
        threat_count = SecurityEvent.query.filter_by(is_threat=True).count()
        
        return jsonify({
            'total_packets': total_packets,
            'protocols': [{'name': p[0], 'value': p[1]} for p in protocols],
            'top_talkers': [{'source': t[0], 'dest': t[1], 'count': t[2]} for t in top_talkers],
            'top_ports': [{'port': p[0], 'count': p[1]} for p in top_ports],
            'threat_count': threat_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/full-analysis', methods=['GET'])
def full_analysis():
    try:
        stats = get_stats().get_json()
        summary = analyze_full_pcap(stats)
        return jsonify({'summary': summary})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    try:
        stats = get_stats().get_json()
        response = analyze_chat(data.get('history', []), stats)
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enrich/<ip>')
def enrich_ip(ip):
    if ip in ip_cache: return jsonify(ip_cache[ip])
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            enriched = {'isp': data.get('isp', 'Unknown'), 'country': data.get('country', 'Unknown'), 'city': data.get('city', 'Unknown')}
            ip_cache[ip] = enriched
            return jsonify(enriched)
    except: pass
    return jsonify({'isp': 'Failed', 'country': 'N/A', 'city': 'N/A'})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    event = SecurityEvent.query.get(data.get('event_id'))
    if not event: return jsonify({'error': 'Not found'}), 404
    summary = analyze_event(event.to_dict())
    event.ai_summary = summary
    db.session.commit()
    return jsonify({'summary': summary})

if __name__ == '__main__':
    with app.app_context():
        # Schema auto-update check
        try:
            db.session.execute(text("SELECT dest_port FROM security_event LIMIT 1"))
        except:
            print("Initializing Elite PacketAI Database...")
            db.drop_all()
            db.create_all()
            
    app.run(debug=True)
