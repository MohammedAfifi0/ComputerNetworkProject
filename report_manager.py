import os
import json
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from collections import defaultdict
from data_manager import data_manager, Scan

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
        scan = data_manager.get_scan(scan_id)
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
    
    def get_vulnerability_analytics(self, scan_id):
        """
        Get vulnerability analytics data for a specific scan
        """
        report_data = self.get_report(scan_id)
        if not report_data:
            return None
        
        analytics = {
            'total_vulnerabilities': 0,
            'hosts_with_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'vulnerabilities_by_host': [],
            'top_vulnerabilities': [],
            'vulnerabilities_by_severity': {
                'critical': [],  # 9.0-10.0
                'high': [],      # 7.0-8.9
                'medium': [],    # 4.0-6.9
                'low': []        # 0.1-3.9
            }
        }
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        vulnerability_counts = defaultdict(int)
        
        for host in report_data['hosts']:
            host_addr = host['addresses'][0]['addr'] if host['addresses'] else 'Unknown'
            host_vulns = []
            
            for port in host['ports']:
                for vuln in port['vulnerabilities']:
                    vuln_id = vuln['id']
                    score = vuln['score']
                    
                    # Convert score to float for comparison
                    try:
                        score_float = float(score) if score != 'N/A' else 0
                    except ValueError:
                        score_float = 0
                    
                    # Categorize by severity
                    if score_float >= 9.0:
                        analytics['critical_count'] += 1
                        analytics['vulnerabilities_by_severity']['critical'].append({
                            'id': vuln_id,
                            'score': score,
                            'host': host_addr,
                            'port': port['portid'],
                            'service': port['service'].get('name', '')
                        })
                    elif score_float >= 7.0:
                        analytics['high_count'] += 1
                        analytics['vulnerabilities_by_severity']['high'].append({
                            'id': vuln_id,
                            'score': score,
                            'host': host_addr,
                            'port': port['portid'],
                            'service': port['service'].get('name', '')
                        })
                    elif score_float >= 4.0:
                        analytics['medium_count'] += 1
                        analytics['vulnerabilities_by_severity']['medium'].append({
                            'id': vuln_id,
                            'score': score,
                            'host': host_addr,
                            'port': port['portid'],
                            'service': port['service'].get('name', '')
                        })
                    elif score_float > 0:
                        analytics['low_count'] += 1
                        analytics['vulnerabilities_by_severity']['low'].append({
                            'id': vuln_id,
                            'score': score,
                            'host': host_addr,
                            'port': port['portid'],
                            'service': port['service'].get('name', '')
                        })
                    
                    # Add to host vulnerabilities
                    host_vulns.append({
                        'id': vuln_id,
                        'score': score,
                        'port': port['portid'],
                        'service': port['service'].get('name', '')
                    })
                    
                    # Count total vulnerabilities
                    analytics['total_vulnerabilities'] += 1
                    
                    # Track unique vulnerability counts
                    vulnerability_counts[vuln_id] += 1
                    
                    # Add to all vulnerabilities list
                    all_vulnerabilities.append({
                        'id': vuln_id,
                        'score': score,
                        'host': host_addr,
                        'port': port['portid'],
                        'service': port['service'].get('name', '')
                    })
            
            if host_vulns:
                analytics['hosts_with_vulnerabilities'] += 1
                analytics['vulnerabilities_by_host'].append({
                    'host': host_addr,
                    'vulnerability_count': len(host_vulns),
                    'vulnerabilities': host_vulns
                })
        
        # Get top vulnerabilities (by count)
        top_vulns = sorted(vulnerability_counts.items(), key=lambda x: x[1], reverse=True)
        for vuln_id, count in top_vulns[:10]:  # Top 10
            # Find an example of this vulnerability to get the score
            example = next((v for v in all_vulnerabilities if v['id'] == vuln_id), None)
            score = example['score'] if example else 'N/A'
            
            analytics['top_vulnerabilities'].append({
                'id': vuln_id,
                'count': count,
                'score': score
            })
        
        # Sort vulnerabilities by severity within each category
        for severity in analytics['vulnerabilities_by_severity']:
            analytics['vulnerabilities_by_severity'][severity].sort(
                key=lambda x: float(x['score']) if x['score'] != 'N/A' else 0, 
                reverse=True
            )
        
        return analytics
        
    def delete_report(self, scan_id):
        """
        Delete a scan report
        """
        scan = data_manager.get_scan(scan_id)
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
