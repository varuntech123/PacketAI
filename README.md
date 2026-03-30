# 🛡️ PacketAI: Industrial-Grade PCAP SIEM & Forensics

**PacketAI** is a high-performance network security platform designed for deep forensic analysis, real-time threat detection, and AI-augmented investigation. It transforms raw PCAP/PCAPNG data into actionable intelligence through a professional SIEM dashboard.

![PacketAI Dashboard Mockup](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80) 
*(Example Security Operations Center theme)*

---

## 🚀 Key Features

### 🔬 Deep Forensic Analysis
- **Advanced Ingestion**: High-capacity parsing of Wireshark captures (TCP/UDP/TLS).
- **Interactive Log**: Filterable forensic logs with detailed metadata extraction.
- **Protocol Distribution**: Visual breakdown of network traffic composition.

### 🧠 AI Intelligence Augmentation
- **Automated Summaries**: AI-driven synthesis of entire forensic sessions.
- **Forensic Q&A**: Interactive terminal-style chat for deep investigation of specific IPs and ports.
- **Heuristic Fallbacks**: Robust rule-based analysis when offline.

### 🚩 SIEM Heuristics
- **Threat Detection**: Real-time detection of SQL/Command injections, SYN scans, and DDoS attempts.
- **Severity Scoring**: Automated color-coded tagging (LOW/MED/HIGH/CRITICAL).
- **IP Enrichment**: Geolocation and ISP intelligence for suspicious source IPs.

---

## 🛠️ Technical Stack
- **Backend**: Python (Flask, SQLAlchemy)
- **Engine**: Tshark (Wireshark command-line)
- **Frontend**: Vanilla JS (Chart.js, Marked.js, Bootstrap 4)
- **AI**: Ollama (Llama 3.2 recommended) / OpenAI compatible

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- **Python 3.9+**
- **Wireshark (tshark)**: Must be installed at `C:\Program Files\Wireshark\tshark.exe` (or update path in `app.py`).
- **Ollama**: (Optional for AI) Install at [ollama.com](https://ollama.com).

### 2. Standard Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/PacketAI.git
cd PacketAI

# Set up virtual environment
python -m venv venv
source venv/Scripts/activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Running the Platform
```bash
# Start the Flask server
python app.py
```
Open your browser to `http://127.0.0.1:5000` to begin.

---

## 📂 Project Structure
- `app.py`: Main API gateway and server logic.
- `models.py`: Database schema for Security Events.
- `ai_analyzer.py`: AI / Heuristic analysis engine.
- `threat_detection.py`: Industrial SIEM rule-set.
- `templates/`: Premium forensic UI dashboard.

---

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

---

**Developed for Industry-Ready Cybersecurity Forensics.**
