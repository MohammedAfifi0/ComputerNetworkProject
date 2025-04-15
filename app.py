import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Use SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///flanscan.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database
db.init_app(app)

# Import modules after app is created to avoid circular imports
from scanner import Scanner
from report_manager import ReportManager
import models

# Create an instance of the scanner
scanner = Scanner()
report_manager = ReportManager()

# Initialize database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    active_scans = models.Scan.query.filter_by(status='running').all()
    return render_template('index.html', active_scans=active_scans)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    scan_name = request.form.get('scan_name', f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    
    if not target:
        flash('Please provide a target IP address or range', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Create a new scan record
        new_scan = models.Scan(
            name=scan_name,
            target=target,
            status='queued',
            start_time=datetime.now()
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan
        scanner.start_scan(new_scan.id, target)
        flash('Scan started successfully', 'success')
    except Exception as e:
        logging.error(f"Error starting scan: {str(e)}")
        flash(f'Error starting scan: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    scan = models.Scan.query.get_or_404(scan_id)
    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'start_time': scan.start_time.isoformat() if scan.start_time else None,
        'end_time': scan.end_time.isoformat() if scan.end_time else None
    })

@app.route('/reports')
def reports():
    all_reports = models.Scan.query.order_by(models.Scan.start_time.desc()).all()
    return render_template('reports.html', reports=all_reports)

@app.route('/view_report/<int:scan_id>')
def view_report(scan_id):
    scan = models.Scan.query.get_or_404(scan_id)
    
    if scan.status != 'completed':
        flash('Report is not yet available', 'warning')
        return redirect(url_for('reports'))
    
    report_data = report_manager.get_report(scan_id)
    return render_template('view_report.html', scan=scan, report=report_data)

@app.route('/delete_report/<int:scan_id>', methods=['POST'])
def delete_report(scan_id):
    scan = models.Scan.query.get_or_404(scan_id)
    
    try:
        # Delete the scan report file if it exists
        report_manager.delete_report(scan_id)
        
        # Delete the scan record from the database
        db.session.delete(scan)
        db.session.commit()
        
        flash('Report deleted successfully', 'success')
    except Exception as e:
        logging.error(f"Error deleting report: {str(e)}")
        flash(f'Error deleting report: {str(e)}', 'danger')
    
    return redirect(url_for('reports'))

@app.route('/cancel_scan/<int:scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    scan = models.Scan.query.get_or_404(scan_id)
    
    if scan.status not in ['queued', 'running']:
        flash('Cannot cancel a scan that is not in progress', 'warning')
        return redirect(url_for('index'))
    
    try:
        scanner.cancel_scan(scan_id)
        scan.status = 'cancelled'
        scan.end_time = datetime.now()
        db.session.commit()
        flash('Scan cancelled successfully', 'success')
    except Exception as e:
        logging.error(f"Error cancelling scan: {str(e)}")
        flash(f'Error cancelling scan: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
