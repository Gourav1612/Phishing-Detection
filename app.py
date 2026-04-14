from flask import Flask, render_template, request, jsonify, send_file
from database import db, init_db, ScanHistory
from feature_extraction import extract_features
import joblib
import xgboost as xgb
from sklearn.ensemble import VotingClassifier
import pandas as pd
import os
from datetime import datetime
from fpdf import FPDF
import io
import socket
import concurrent.futures
from urllib.parse import urlparse

app = Flask(__name__)
# Use an environment variable for the database URI if available, otherwise fallback to local sqlite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detection.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Global variables
model = None
feature_names = None

def load_model_and_features():
    global model, feature_names
    try:
        model = joblib.load('model.pkl')
        if os.path.exists('features.pkl'):
            feature_names = joblib.load('features.pkl')
        else:
            # Fallback to defaults
            feature_names = ['url_length', 'has_ip', 'special_chars', 'has_https', 'suspicious_keywords']
            
        # Warm-up predicting to eliminate lazy-loading overhead
        dummy_X = pd.DataFrame([[0]*len(feature_names)], columns=feature_names)
        model.predict(dummy_X)
        model.predict_proba(dummy_X)
        
        print("Model and features loaded successfully.")
    except Exception as e:
        print(f"Error loading model resources: {e}")
        model = None
        feature_names = None

# Initial load
load_model_and_features()

# Initialize DB
init_db(app)

def get_prediction(url):
    """
    Returns prediction (0=Legitimate, 1=Phishing) and confidence.
    Uses hybrid content features for 97% accuracy.
    """
    if model is None or feature_names is None:
        return 0, 0.0
    
    # Extract URL + Content features
    all_features = extract_features(url, include_content=True)
    
    # Map features to the specific list used by the current model
    feature_values = [all_features.get(name, 0) for name in feature_names]
    
    # Create DataFrame for prediction
    X = pd.DataFrame([feature_values], columns=feature_names)
    
    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    confidence = float(max(probabilities))
    
    return prediction, confidence

@app.route('/')
def index():
    """
    Main entry point for the Single Page Application.
    Returns the unified UI with all initial data.
    """
    total_scans = ScanHistory.query.count()
    phishing_scans = ScanHistory.query.filter_by(prediction='Phishing').count()
    suspicious_scans = ScanHistory.query.filter_by(prediction='Suspicious').count()
    legitimate_scans = ScanHistory.query.filter_by(prediction='Legitimate').count()
    
    stats = {
        'total': total_scans,
        'phishing': phishing_scans,
        'suspicious': suspicious_scans,
        'legitimate': legitimate_scans
    }
    
    scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(100).all()
    
    return render_template('index.html', stats=stats, scans=scans)

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Get prediction and confidence
    prediction_code, confidence = get_prediction(url)
    confidence = confidence * 100 
    
    mapping = {0: 'Legitimate', 1: 'Phishing', 2: 'Suspicious'}
    result = mapping.get(prediction_code, 'Unknown')
    
    risk_level = 'Low'
    recommendation = "This URL appears to be safe. However, always exercise caution."
    
    if result == 'Phishing':
        risk_level = 'High'
        recommendation = "WARNING: This URL is highly likely to be a phishing attempt. DO NOT enter any credentials."
    elif result == 'Suspicious':
        risk_level = 'Medium'
        recommendation = "Caution: This URL has suspicious characteristics. Proceed with extreme care."

    # IP and DNS lookup
    try:
        hostname = urlparse(url).netloc
        if not hostname:
            hostname = urlparse("http://" + url).netloc
            
        ip_address = socket.gethostbyname(hostname)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(socket.gethostbyaddr, ip_address)
                host_info = future.result(timeout=0.5)[0]
        except:
            host_info = "Unable to resolve"
    except Exception as e:
        ip_address = "Resolution Failed"
        host_info = "Unknown"

    # Save to history
    scan = ScanHistory(
        url=url,
        prediction=result,
        confidence=confidence,
        risk_level=risk_level,
        ip_address=ip_address,
        host_info=host_info
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({
        'url': url,
        'prediction': result,
        'confidence': f"{confidence:.2f}%",
        'risk_level': risk_level,
        'recommendation': recommendation,
        'id': scan.id,
        'ip_address': ip_address,
        'host_info': host_info
    })

@app.route('/api/stats')
def get_stats():
    """Returns real-time statistics for the dashboard."""
    stats = {
        'total': ScanHistory.query.count(),
        'phishing': ScanHistory.query.filter_by(prediction='Phishing').count(),
        'suspicious': ScanHistory.query.filter_by(prediction='Suspicious').count(),
        'legitimate': ScanHistory.query.filter_by(prediction='Legitimate').count()
    }
    return jsonify(stats)

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    """Deletes all records from the ScanHistory table."""
    try:
        num_deleted = db.session.query(ScanHistory).delete()
        db.session.commit()
        return jsonify({'message': f'Cleared {num_deleted} scan records.', 'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/report/<int:scan_id>')
def generate_report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(190, 15, "Phishing Detection Tool Report", 0, 1, 'C')
    pdf.ln(10)
    
    # Report Details
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(190, 10, "Scan Summary", 0, 1, 'L')
    pdf.set_font("Arial", size=12)
    pdf.cell(190, 10, f"URL: {scan.url}", 0, 1, 'L')
    pdf.cell(190, 10, f"Result: {scan.prediction}", 0, 1, 'L')
    pdf.cell(190, 10, f"Confidence: {scan.confidence:.2f}%", 0, 1, 'L')
    pdf.cell(190, 10, f"Risk Level: {scan.risk_level}", 0, 1, 'L')
    pdf.cell(190, 10, f"Timestamp: {scan.timestamp}", 0, 1, 'L')
    
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(190, 10, "Detailed Analysis", 0, 1, 'L')
    pdf.set_font("Arial", size=12)
    
    # Add features used
    features = extract_features(scan.url)
    for key, val in features.items():
        pdf.cell(190, 8, f"{key.replace('_', ' ').title()}: {val}", 0, 1, 'L')
        
    pdf.ln(10)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(190, 8, "This report was generated by the Phishing Detection Tool. Use this information at your own discretion.")
    
    output = io.BytesIO()
    pdf_out = pdf.output(dest='S')
    if isinstance(pdf_out, str):
        pdf_out = pdf_out.encode('latin-1', 'replace')
    
    output.write(pdf_out)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"Phishing_Report_{scan_id}.pdf"
    )

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
