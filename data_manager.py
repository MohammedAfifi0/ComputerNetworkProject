import os
import json
import logging
from datetime import datetime
import shutil

class Scan:
    """
    Scan class to replace the database model
    """
    def __init__(self, id=None, name=None, target=None, status='queued', 
                 start_time=None, end_time=None, report_path=None):
        self.id = id
        self.name = name
        self.target = target
        self.status = status  # queued, running, completed, failed, cancelled
        self.start_time = start_time or datetime.now()
        self.end_time = end_time
        self.report_path = report_path
    
    def to_dict(self):
        """Convert object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'target': self.target,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'report_path': self.report_path
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create object from dictionary"""
        scan = cls(
            id=data.get('id'),
            name=data.get('name'),
            target=data.get('target'),
            status=data.get('status', 'queued'),
            report_path=data.get('report_path')
        )
        
        # Convert string timestamps to datetime objects
        if data.get('start_time'):
            scan.start_time = datetime.fromisoformat(data.get('start_time'))
        if data.get('end_time'):
            scan.end_time = datetime.fromisoformat(data.get('end_time'))
            
        return scan
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target}>'
    
    def duration(self):
        """Calculate scan duration"""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return None
    
    def is_active(self):
        """Check if scan is still active"""
        return self.status in ['queued', 'running']


class DataManager:
    """
    Class to manage data storage in JSON files
    """
    def __init__(self):
        self.data_dir = os.path.join(os.getcwd(), 'data')
        self.scans_file = os.path.join(self.data_dir, 'scans.json')
        self.reports_dir = os.path.join(os.getcwd(), 'reports')
        
        # Create data directory if it doesn't exist
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        # Create scans file if it doesn't exist
        if not os.path.exists(self.scans_file):
            with open(self.scans_file, 'w') as f:
                json.dump([], f)
    
    def get_all_scans(self):
        """Get all scans"""
        try:
            with open(self.scans_file, 'r') as f:
                data = json.load(f)
                return [Scan.from_dict(scan_data) for scan_data in data]
        except Exception as e:
            logging.error(f"Error reading scans file: {str(e)}")
            return []
    
    def get_scan(self, scan_id):
        """Get a specific scan by ID"""
        scans = self.get_all_scans()
        for scan in scans:
            if scan.id == scan_id:
                return scan
        return None
    
    def add_scan(self, scan):
        """Add a new scan"""
        scans = self.get_all_scans()
        
        # Generate new ID if not provided
        if scan.id is None:
            scan.id = self._generate_id(scans)
            
        # Add scan to list
        scans.append(scan)
        
        # Save scans list
        self._save_scans(scans)
        
        return scan.id
    
    def update_scan(self, scan):
        """Update an existing scan"""
        scans = self.get_all_scans()
        
        # Find and update the scan
        for i, existing_scan in enumerate(scans):
            if existing_scan.id == scan.id:
                scans[i] = scan
                break
        
        # Save updated scans list
        self._save_scans(scans)
        
        return scan.id
    
    def delete_scan(self, scan_id):
        """Delete a scan"""
        scans = self.get_all_scans()
        
        # Filter out the scan to delete
        updated_scans = [scan for scan in scans if scan.id != scan_id]
        
        # Save updated scans list
        self._save_scans(updated_scans)
        
        return True
    
    def _save_scans(self, scans):
        """Save scans list to file"""
        try:
            # Convert scan objects to dictionaries for JSON serialization
            scan_dicts = [scan.to_dict() for scan in scans]
            
            with open(self.scans_file, 'w') as f:
                json.dump(scan_dicts, f, indent=2)
                
            return True
        except Exception as e:
            logging.error(f"Error saving scans file: {str(e)}")
            return False
    
    def _generate_id(self, scans):
        """Generate a new unique ID for a scan"""
        if not scans:
            return 1
            
        # Get the maximum ID
        max_id = max(scan.id for scan in scans if scan.id is not None)
        
        # Return next ID
        return max_id + 1
    
    def get_active_scans(self):
        """Get all active scans (queued or running)"""
        scans = self.get_all_scans()
        return [scan for scan in scans if scan.is_active()]
    
    def get_completed_scans(self):
        """Get all completed scans"""
        scans = self.get_all_scans()
        return [scan for scan in scans if scan.status == 'completed']
    
    def delete_scan_report(self, scan_id):
        """Delete a scan's report files"""
        try:
            scan_dir = os.path.join(self.reports_dir, f"scan_{scan_id}")
            if os.path.exists(scan_dir):
                shutil.rmtree(scan_dir)
            return True
        except Exception as e:
            logging.error(f"Error deleting report for scan {scan_id}: {str(e)}")
            return False

# Create a global instance
data_manager = DataManager()