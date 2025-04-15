import os
import subprocess
import threading
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from app import db
from models import Scan

class Scanner:
    def __init__(self):
        self.active_scans = {}
        self.reports_dir = os.path.join(os.getcwd(), 'reports')
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def _run_scan(self, scan_id, target):
        """
        Run the Flan Scan Docker container against the specified target
        """
        logging.debug(f"Starting scan {scan_id} for target {target}")
        
        # Update scan status to running
        scan = Scan.query.get(scan_id)
        if not scan:
            logging.error(f"Scan {scan_id} not found")
            return
        
        scan.status = 'running'
        db.session.commit()
        
        # Create a directory for this scan's reports
        scan_dir = os.path.join(self.reports_dir, f"scan_{scan_id}")
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
        
        try:
            # Prepare the Docker command to run Flan Scan
            # Note: We're using a subprocess to run Docker, which must be installed on the host
            docker_cmd = [
                "docker", "run", "--rm", 
                "-v", f"{scan_dir}:/shared",
                "quay.io/flanscan/flanscan",
                "-t", target,
                "-o", "/shared"
            ]
            
            # Run the Docker command
            process = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store the process in active_scans for potential cancellation
            self.active_scans[scan_id] = process
            
            # Wait for the process to complete
            stdout, stderr = process.communicate()
            
            # Process has completed, remove from active_scans
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            
            # Check if the scan completed successfully
            if process.returncode == 0:
                # Parse the report and update the database
                xml_report_path = os.path.join(scan_dir, 'report.xml')
                if os.path.exists(xml_report_path):
                    scan.status = 'completed'
                    scan.end_time = datetime.now()
                    scan.report_path = xml_report_path
                    db.session.commit()
                    logging.debug(f"Scan {scan_id} completed successfully")
                else:
                    scan.status = 'failed'
                    scan.end_time = datetime.now()
                    db.session.commit()
                    logging.error(f"Scan {scan_id} output file not found")
            else:
                # Scan failed
                scan.status = 'failed'
                scan.end_time = datetime.now()
                db.session.commit()
                logging.error(f"Scan {scan_id} failed: {stderr}")
                
                # Write error to a file for reference
                error_file = os.path.join(scan_dir, 'error.log')
                with open(error_file, 'w') as f:
                    f.write(f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
        
        except Exception as e:
            logging.error(f"Error during scan {scan_id}: {str(e)}")
            # Mark the scan as failed
            scan.status = 'failed'
            scan.end_time = datetime.now()
            db.session.commit()
    
    def start_scan(self, scan_id, target):
        """
        Start a new scan in a separate thread
        """
        thread = threading.Thread(target=self._run_scan, args=(scan_id, target))
        thread.daemon = True
        thread.start()
        return True
    
    def cancel_scan(self, scan_id):
        """
        Cancel a running scan
        """
        if scan_id in self.active_scans:
            process = self.active_scans[scan_id]
            if process:
                process.terminate()
                del self.active_scans[scan_id]
                return True
        return False
    
    def get_scan_status(self, scan_id):
        """
        Get the current status of a scan
        """
        scan = Scan.query.get(scan_id)
        if scan:
            return {
                'id': scan.id,
                'status': scan.status,
                'start_time': scan.start_time,
                'end_time': scan.end_time
            }
        return None
