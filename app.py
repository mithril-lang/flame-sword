from flask import Flask, render_template, request, jsonify, session
import uuid
import threading
import time
from datetime import datetime
from modules.subdomains import SubdomainEnumerator
from modules.real_ip_discovery import RealIPDiscovery
from modules.port_scanner import PortScanner
from modules.dns_scan import DNSScanner
from modules.ssl_scanner import SSLScanner
from modules.tech_detector import TechnologyDetector
from modules.enumeration import EmailUserEnumerator
from modules.FastAnalyst import FastSecurityAnalyst # Import FastSecurityAnalyst
from modules.AI_analyst import AIAnalyst
from utils.reporting import ReportGenerator
from utils.helpers import validate_domain, sanitize_domain
import os
from dotenv import load_dotenv
from modules.mithril_api import MithrilAPI, MithrilAPIError
from modules.secrets import load_mithril_key
from modules.storage import ScanStore
from modules.evidence import normalize, assess, SECTIONS

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
load_mithril_key()

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        # If it's already a string, parse it to datetime first
        value = datetime.fromisoformat(value)
    return value.strftime(format)


scan_results = {}
scan_status = {}
store = ScanStore()

def checkpoint(scan_id):
    store.save(scan_id, scan_status[scan_id], scan_results[scan_id])

def module_finished(scan_id, module):
    report = scan_results[scan_id]
    data = report.get(SECTIONS[module])
    state = "failed" if isinstance(data, dict) and data.get("error") else "completed"
    report.setdefault("module_status", {})[module] = state
    checkpoint(scan_id)


@app.context_processor
def inject_now():
    return {'now': datetime.now, 'mithril': MithrilAPI().configuration()}

@app.route('/')
def index():
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    options = data.get('options', {
        'subdomains': True,
        'ports': True,
        'port_scan_choice': 'all_subdomains', # New option for port scan
        'dns': True,
        'ssl': True,
        'tech': True,
        'email': True,
        'security': True,
        'ai': True,
        'intensity': 'normal'
    })
    
    if not validate_domain(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    domain = sanitize_domain(domain)
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_task': 'Initializing scan...',
        'start_time': datetime.now(),
        'domain': domain,
        'options': options
    }
    
    # Initialize results structure
    scan_results[scan_id] = {
        'domain': domain,
        'subdomains': [],
        'port_scan': [],
        'dns_records': {},
        'ssl_scan': {},
        'tech_detection': {},
        'email_enumeration': {},
        'security_analysis': {},
        'ai_analysis': {},
        'scan_id': scan_id,
        'timestamp': datetime.now().isoformat(),
        'options': options,
        'module_status': {name: 'pending' if options.get(name, True) else 'skipped'
                          for name in SECTIONS if name != 'headers'}
    }
    checkpoint(scan_id)
    
    # Start background scan
    thread = threading.Thread(target=run_scan, args=(scan_id, domain, options))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})


def run_scan(scan_id, domain, options):
    try:
            # Create application context for the background thread
            total_steps = sum(1 for opt in options.values() if isinstance(opt, bool) and opt)
            completed_steps = 0
        
            # Configure scan intensity
            max_subdomains = {
                'light': 10,
                'normal': 30,
                'aggressive': 100
            }.get(options.get('intensity', 'normal'), 30)

            subdomains = [] # Initialize subdomains list
            if options.get('subdomains', True):
                # Update status
                scan_status[scan_id]['current_task'] = 'Enumerating subdomains...'
                scan_status[scan_id]['progress'] = 10
            
                # Run subdomain enumeration
                subdomain_enum = SubdomainEnumerator()
                subdomains = subdomain_enum.enumerate(domain)
                scan_results[scan_id]['subdomains'] = subdomains
                scan_status[scan_id]['progress'] = 20
                module_finished(scan_id, "subdomains")

            # Run email enumeration if selected
            email_results = {} # Initialize email_results
            if options.get('email', True):
                # Run email enumeration
                scan_status[scan_id]['current_task'] = 'Enumerating email patterns...'
                email_enum = EmailUserEnumerator()
                email_results = email_enum.find_email_patterns(domain)
                scan_results[scan_id]['email_enumeration'] = email_results
                scan_status[scan_id]['progress'] = 30
                module_finished(scan_id, "email")

            # Run port scanning on active subdomains
            if options.get('ports', True):
                scan_status[scan_id]['current_task'] = 'Scanning ports...'
                
                # Determine targets based on port_scan_choice
                port_scan_choice = options.get('port_scan_choice', 'all_subdomains')
                targets_for_port_scan = []

                if port_scan_choice == 'critical_only':
                    scan_status[scan_id]['current_task'] = 'Identifying critical subdomains for port scan...'
                    security_analyst = FastSecurityAnalyst()
                    # Perform a preliminary analysis to get critical subdomains
                    analysis_data = security_analyst._prepare_analysis_data(domain, subdomains)
                    critical_subdomains_data = analysis_data['categories']['critical']
                    
                    for category_list in critical_subdomains_data.values():
                        for s in category_list:
                            targets_for_port_scan.append(s['subdomain'])
                    
                    scan_status[scan_id]['current_task'] = f'Scanning ports on {len(targets_for_port_scan)} critical subdomains...'
                    print(f"Critical subdomains for port scan: {targets_for_port_scan}")

                else: # Default to 'all_subdomains'
                    active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                    targets_for_port_scan = [s['subdomain'] for s in active_subdomains]
                    scan_status[scan_id]['current_task'] = f'Scanning ports on {len(targets_for_port_scan)} active subdomains...'
                    print(f"All active subdomains for port scan: {targets_for_port_scan}")
            
                port_scanner = PortScanner()
                port_results = port_scanner.batch_scan(targets_for_port_scan, ports='21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017')
                print(f"Port scan raw results: {port_results}")
                scan_results[scan_id]['port_scan'] = [r for r in port_results if r is not None]
                scan_status[scan_id]['progress'] = 40
                module_finished(scan_id, "ports")
            
            # Run DNS scanning
            if options.get('dns', True):
                scan_status[scan_id]['current_task'] = 'Scanning DNS records...'
            
                dns_scanner = DNSScanner(domain)
                # Use aggressive mode if intensity is set to aggressive
                aggressive = options.get('intensity', 'normal') == 'aggressive'
                scan_results[scan_id]['dns_records'] = dns_scanner.scan(aggressive=aggressive)
                scan_status[scan_id]['progress'] = 50
                module_finished(scan_id, "dns")


            if options.get('real_ip', True):
                scan_status[scan_id]['current_task'] = 'Discovering real IPs...'
                real_ip_discovery = RealIPDiscovery()
    
                # Pass existing data instead of doing new scans
                subdomains_data = scan_results[scan_id].get('subdomains', [])
                dns_data = scan_results[scan_id].get('dns_records', {})
    
                # Run discovery and get the filtered IPs
                real_ips = real_ip_discovery.discover_real_ips(domain, subdomains_data, dns_data)
    
                # Prepare results for JSON serialization
                ip_results = []
                for ip in real_ips:
                    ip_results.append({
                        'ip': ip,
                        'score': 10,  # Default score
                        'responds': True,  # Default status
                        'methods': ['multiple']  # Default methods
                    })
    
                scan_results[scan_id]['real_ip'] = {
                    'origin_ips': ip_results,
                    # Fix: Access CDN ranges through the ip_utils attribute
                    'techniques_used': list(real_ip_discovery.ip_utils.cdn_ranges.keys())
                }
                scan_status[scan_id]['progress'] = 60  # Updated progress value
                module_finished(scan_id, "real_ip")


            # In the run_scan function, update the SSL scan section:
            if options.get('ssl', True):
                scan_status[scan_id]['current_task'] = 'Scanning SSL/TLS configuration...'
                ssl_scanner = SSLScanner()
    
                # Scan both the main domain and active subdomains
                ssl_results = {
                    'main_domain': ssl_scanner.scan(domain)
                    }
    
                # Scan active subdomains that support HTTPS
                active_https_subdomains = [s for s in subdomains if s.get('https_status')]
                for subdomain in active_https_subdomains[:15]:  # Limit to 5 for performance
                    try:
                        ssl_results[subdomain['subdomain']] = ssl_scanner.scan(subdomain['subdomain'])
                    except Exception as e:
                        print(f"SSL scan failed for {subdomain['subdomain']}: {e}")
                        ssl_results[subdomain['subdomain']] = {'error': str(e)}
    
                scan_results[scan_id]['ssl_scan'] = ssl_results
                scan_status[scan_id]['progress'] = 70
                module_finished(scan_id, "ssl")

            # Run technology detection
            if options.get('tech', True):
                active_subdomains = [s for s in subdomains if s.get('http_status') or s.get('https_status')]
                scan_status[scan_id]['current_task'] = 'Detecting technologies...'
                tech_detector = TechnologyDetector()
                tech_results = {}
            
                for subdomain in active_subdomains[:15]:  # Limit to 5 for demo
                    url = f"https://{subdomain['subdomain']}" if subdomain.get('https_status') else f"http://{subdomain['subdomain']}"
                    try:
                        tech_data = tech_detector.detect_technologies(url)
                        tech_results[url] = tech_data
                    except Exception as e:
                        print(f"Tech detection failed for {url}: {e}")
                        continue
                    
                scan_results[scan_id]['tech_detection'] = tech_results
                scan_status[scan_id]['progress'] = 80
                module_finished(scan_id, "tech")
            
            # Run security analysis
            scan_status[scan_id]['current_task'] = 'Running security analysis...'
            security_analysis = {}
            if options.get('security', True):
                security_analyst = FastSecurityAnalyst()
                security_analysis = security_analyst.analyze_subdomains(domain, subdomains)
            scan_results[scan_id]['security_analysis'] = security_analysis
            if options.get('security', True):
                module_finished(scan_id, 'security')
            
            # Add email enumeration results to security analysis
            if options.get('email', True):
                security_analysis['email_analysis'] = email_results
                scan_results[scan_id]['security_analysis'] = security_analysis
            
            scan_results[scan_id]['evidence'] = normalize(scan_results[scan_id])
            # Run AI analysis
            if options.get('ai', True):
                scan_status[scan_id]['current_task'] = 'Generating Mithril AI insights...'
                ai_analyst = AIAnalyst()
                scan_results[scan_id]['ai_analysis'] = ai_analyst.analyze_results(scan_results[scan_id])
            
            scan_status[scan_id]['progress'] = 100
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['current_task'] = 'Scan completed'
            scan_status[scan_id]['end_time'] = datetime.now()

            duration = scan_status[scan_id]['end_time'] - scan_status[scan_id]['start_time']
            total_seconds = int(duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            scan_status[scan_id]['duration'] = f"{hours}h {minutes}m {seconds}s"
            
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['error'] = str(e)
        scan_status[scan_id]['progress'] = 0
        print(f"Scan error for {scan_id}: {e}")
    finally:
        checkpoint(scan_id)

@app.route('/scan_status/<scan_id>')
def get_scan_status(scan_id):
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = scan_status[scan_id].copy()
    
    # Convert datetime objects to strings
    if isinstance(status.get('start_time'), datetime):
        status['start_time'] = status['start_time'].isoformat()
    if isinstance(status.get('end_time'), datetime):
        status['end_time'] = status['end_time'].isoformat()
    
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    if 'security_analysis' not in scan_results[scan_id]:
        evidence = normalize(scan_results[scan_id])
        return jsonify(evidence=evidence, assessment=assess(evidence))
    
    # Add duration to results if available
    if scan_id in scan_status and 'duration' in scan_status[scan_id]:
        scan_results[scan_id]['duration'] = scan_status[scan_id]['duration']
    
    return render_template('results.html', 
                         results=scan_results[scan_id], 
                         scan_id=scan_id,
                        scan_status=scan_status)

@app.route('/api/results/<scan_id>')
def api_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/export/<scan_id>')
def export_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    format_type = request.args.get('format', 'json')
    
    report_gen = ReportGenerator()
    
    if format_type == 'pdf':
        pdf_content = report_gen.generate_pdf(scan_results[scan_id])
        return pdf_content, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.pdf'
        }
    else:
        json_content = report_gen.generate_json(scan_results[scan_id])
        return json_content, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=security_report_{scan_id}.json'
        }

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'analysis_type': 'Comprehensive Security Analysis'
    })

@app.route('/api/capabilities')
def get_capabilities():
    return jsonify({
        'analysis_type': 'Comprehensive Security Analysis',
        'features': [
            'Subdomain enumeration',
            'Port scanning',
            'Technology detection',
            'Email/user enumeration',
            'Security risk assessment'
        ],
        'modules': [
            'SubdomainEnumerator',
            'PortScanner',
            'TechnologyDetector',
            'EmailUserEnumerator',
            'FastSecurityAnalyst'
        ]
    })

@app.route('/api/mithril/status')
def mithril_status():
    return jsonify(MithrilAPI().configuration())


@app.route('/api/mithril/check', methods=['POST'])
def mithril_check():
    client = MithrilAPI()
    try:
        models = client.models()
        return jsonify(**client.configuration(), reachable=True, models=models,
                       model_available=client.model in models,
                       inference_verified=False)
    except MithrilAPIError as error:
        return jsonify(**client.configuration(), reachable=False, error=str(error)), 502


if __name__ == '__main__':
    for scan_id, (saved_status, saved_report) in store.restore().items():
        scan_status[scan_id] = saved_status
        scan_results[scan_id] = saved_report
    port = int(os.getenv('FLAME_SWORD_PORT', '5055'))
    print(f"Flame Sword: http://127.0.0.1:{port}")
    app.run(debug=False, host='127.0.0.1', port=port)
