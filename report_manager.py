import os
import json
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from models import Scan
from app import db

class ReportManager:
    def __init__(self):
        self.reports_dir = os.path.join(os.getcwd(), 'reports')
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def get_report(self, scan_id):
        """
        Get the parsed report data for a specific scan
        """
        scan = Scan.query.get(scan_id)
        if not scan or not scan.report_path or not os.path.exists(scan.report_path):
            return None
        
        try:
            # Parse the XML report into a structured format
            report_data = self._parse_xml_report(scan.report_path)
            return report_data
        except Exception as e:
            logging.error(f"Error parsing report for scan {scan_id}: {str(e)}")
            return None
    
    def _parse_xml_report(self, xml_path):
        """
        Parse the Nmap XML report into a structured format
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Basic scan information
            scan_info = {
                'scanner': root.get('scanner', 'Unknown'),
                'version': root.get('version', 'Unknown'),
                'scan_time': root.get('start', 'Unknown'),
                'hosts': []
            }
            
            # Parse host information
            for host in root.findall('.//host'):
                host_data = {
                    'status': host.find('.//status').get('state', 'unknown') if host.find('.//status') is not None else 'unknown',
                    'addresses': [],
                    'hostnames': [],
                    'ports': []
                }
                
                # Get IP addresses
                for addr in host.findall('.//address'):
                    host_data['addresses'].append({
                        'addr': addr.get('addr', ''),
                        'addrtype': addr.get('addrtype', '')
                    })
                
                # Get hostnames
                for hostname in host.findall('.//hostname'):
                    host_data['hostnames'].append({
                        'name': hostname.get('name', ''),
                        'type': hostname.get('type', '')
                    })
                
                # Get ports and services
                for port in host.findall('.//port'):
                    port_data = {
                        'protocol': port.get('protocol', ''),
                        'portid': port.get('portid', ''),
                        'state': port.find('.//state').get('state', '') if port.find('.//state') is not None else 'unknown',
                        'service': {},
                        'vulnerabilities': []
                    }
                    
                    # Get service information
                    service = port.find('.//service')
                    if service is not None:
                        port_data['service'] = {
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        }
                    
                    # Get vulnerability information (if present)
                    for script in port.findall('.//script'):
                        if script.get('id') == 'vulners':
                            output = script.get('output', '')
                            for line in output.splitlines():
                                if 'CVE-' in line:
                                    # Extract CVE information
                                    parts = line.strip().split('\t')
                                    if len(parts) >= 2:
                                        cve_id = parts[0].strip()
                                        score = parts[1].strip() if len(parts) > 1 else "N/A"
                                        port_data['vulnerabilities'].append({
                                            'id': cve_id,
                                            'score': score
                                        })
                    
                    host_data['ports'].append(port_data)
                
                scan_info['hosts'].append(host_data)
            
            return scan_info
        
        except Exception as e:
            logging.error(f"Error parsing XML report: {str(e)}")
            raise
    
    def delete_report(self, scan_id):
        """
        Delete a scan report
        """
        scan = Scan.query.get(scan_id)
        if not scan:
            return False
        
        try:
            # Delete the report directory
            scan_dir = os.path.join(self.reports_dir, f"scan_{scan_id}")
            if os.path.exists(scan_dir):
                import shutil
                shutil.rmtree(scan_dir)
            
            return True
        except Exception as e:
            logging.error(f"Error deleting report for scan {scan_id}: {str(e)}")
            return False
