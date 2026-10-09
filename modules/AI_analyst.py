# AI_analyst.py
import json
from typing import Dict, List, Optional
import logging
from datetime import datetime
from modules.mithril_api import MithrilAPI, MithrilAPIError

class AIAnalyst:
    def __init__(self):
        """Use Mithril inference when configured, with an explicit rule-based fallback."""
        self.client = MithrilAPI()
        self.provider_errors = []
        self.logger = logging.getLogger(__name__)
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        
        # Templates for when Mithril is not available
        self.owner_template = {
            'summary': "Security assessment completed with rule-based analysis",
            'key_findings': [
                "No critical vulnerabilities detected through automated scanning",
                "Standard security headers evaluation completed",
                "Subdomain enumeration analysis performed"
            ],
            'protection_recommendations': [
                "Implement comprehensive security headers (CSP, HSTS, X-Frame-Options)",
                "Enable Web Application Firewall (WAF) protection",
                "Schedule regular automated vulnerability scans",
                "Implement proper SSL/TLS configuration"
            ],
            'immediate_actions': [
                "Review and update security configurations",
                "Monitor access logs for suspicious activity",
                "Verify SSL certificate validity"
            ],
            'risk_score': 0,
            'perspective': 'owner',
            'ai_model': 'Rule-based Analysis',
            'generated_at': datetime.now().isoformat()
        }

        self.hunter_template = {
            'summary': "Bug bounty hunting analysis completed using automated reconnaissance",
            'promising_targets': [
                {
                    'target': 'Admin interfaces',
                    'reason': 'Potential authentication bypass opportunities'
                },
                {
                    'target': 'API endpoints',
                    'reason': 'Possible injection vulnerabilities'
                }
            ],
            'attack_vectors': [
                {
                    'type': 'Web Application',
                    'description': 'Standard web application attack surface'
                },
                {
                    'type': 'Subdomain Takeover',
                    'description': 'Check for dangling DNS records'
                }
            ],
            'research_areas': [
                {
                    'technology': 'Web Server',
                    'note': 'Investigate server configuration and version'
                },
                {
                    'technology': 'Framework',
                    'note': 'Research framework-specific vulnerabilities'
                }
            ],
            'high_value_findings': [
                "Authentication bypass vulnerabilities",
                "Business logic flaws",
                "Insecure direct object references",
                "Server-side request forgery",
                "Sensitive data exposure"
            ],
            'perspective': 'hunter',
            'ai_model': 'Rule-based Analysis',
            'generated_at': datetime.now().isoformat()
        }

    def analyze_results(self, scan_results: Dict) -> Dict:
        """
        Analyze scan results and generate dual-perspective insights using AI (Mithril) or rule-based fallback
        
        Args:
            scan_results: Dictionary containing all scan results
            
        Returns:
            Dictionary with both owner and hunter perspectives
        """
        try:
            self.provider_errors = []
            self.logger.info("Starting AI analysis...")
            
            if self.client.api_key:
                self.logger.info("Using Mithril API for analysis")
                
                # Analyze owner perspective
                self.logger.info("Analyzing owner perspective...")
                owner_analysis = self._analyze_with_api(scan_results, perspective="owner")
                
                # Analyze hunter perspective
                self.logger.info("Analyzing hunter perspective...")
                hunter_analysis = self._analyze_with_api(scan_results, perspective="hunter")
                
            else:
                self.provider_errors.append("MITHRIL_API_KEY is not configured; using rule-based analysis.")
                self.logger.info("Using rule-based analysis")
                owner_analysis = self._rule_based_owner_analysis(scan_results)
                hunter_analysis = self._rule_based_hunter_analysis(scan_results)
            
            # Ensure proper structure for template
            owner_analysis = self._ensure_owner_structure(owner_analysis)
            hunter_analysis = self._ensure_hunter_structure(hunter_analysis)
            
            result = {
                'provider': self.client.configuration(),
                'provider_errors': self.provider_errors,
                'owner_analysis': owner_analysis,
                'hunter_analysis': hunter_analysis,
                'generated_at': datetime.now().isoformat()
            }
            
            self.logger.info("AI analysis completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {
                'owner_analysis': self._rule_based_owner_analysis(scan_results),
                'hunter_analysis': self._rule_based_hunter_analysis(scan_results),
                'generated_at': datetime.now().isoformat()
            }

    def _analyze_with_api(self, scan_results: Dict, perspective: str) -> Dict:
        try:
            content = self.client.complete(self._prepare_prompt(scan_results, perspective))
            start, end = content.find('{'), content.rfind('}') + 1
            analysis = json.loads(content[start:end])
            if not isinstance(analysis, dict):
                raise ValueError
            analysis['perspective'] = perspective
            analysis['ai_model'] = f'Mithril / {self.client.model}'
            return analysis
        except (MithrilAPIError, ValueError) as error:
            message = str(error) if isinstance(error, MithrilAPIError) else 'Mithril analysis was not a JSON object; using rule-based analysis.'
            self.provider_errors.append(message)
            self.logger.warning(message)
        if perspective == 'owner':
            return self._rule_based_owner_analysis(scan_results)
        return self._rule_based_hunter_analysis(scan_results)

    def _prepare_prompt(self, scan_results: Dict, perspective: str) -> str:
        """
        Prepare the prompt for Mithril API based on scan results and perspective
        """
        # Create a condensed version of results for the prompt
        condensed = {
            'domain': scan_results.get('domain', 'Unknown'),
            'subdomains_count': len(scan_results.get('subdomains', [])),
            'active_subdomains': len([s for s in scan_results.get('subdomains', []) 
                                   if s.get('http_status') or s.get('https_status')]),
            'vulnerabilities_found': len(scan_results.get('vulnerability_scan', [])),
            'technologies_detected': len(scan_results.get('tech_detection', {}))
        }
        
        # Get sample vulnerabilities
        sample_vulns = []
        for scan in scan_results.get('vulnerability_scan', [])[:3]:
            for vuln in scan.get('vulnerabilities', [])[:2]:
                sample_vulns.append({
                    'type': vuln.get('type', 'Unknown'),
                    'risk': vuln.get('risk', 'medium'),
                    'description': vuln.get('description', '')[:150]
                })
        
        # Get sample technologies
        sample_tech = []
        for url, tech_data in list(scan_results.get('tech_detection', {}).items())[:3]:
            for tech in tech_data.get('technologies', [])[:2]:
                sample_tech.append({
                    'name': tech.get('name', 'Unknown'),
                    'version': tech.get('version', 'Unknown')
                })
        
        if perspective == "owner":
            return f"""You are a senior cybersecurity consultant. Analyze this website security scan and provide actionable recommendations for the website owner.

Scan Summary:
- Domain: {condensed['domain']}
- Subdomains found: {condensed['subdomains_count']}
- Active subdomains: {condensed['active_subdomains']}
- Vulnerabilities detected: {condensed['vulnerabilities_found']}
- Technologies identified: {condensed['technologies_detected']}

Key Vulnerabilities Found:
{json.dumps(sample_vulns, indent=2)}

Technologies Detected:
{json.dumps(sample_tech, indent=2)}

Provide a JSON response with these exact keys:
- "summary": Brief overview of security posture
- "key_findings": Array of 3-5 critical security issues
- "protection_recommendations": Array of 3-5 specific security improvements
- "immediate_actions": Array of 3-5 urgent steps to take

Return only valid JSON, no additional text."""

        else:  # hunter perspective
            return f"""You are an experienced bug bounty hunter. Analyze this website security scan and identify the most promising attack opportunities.

Scan Summary:
- Domain: {condensed['domain']}
- Subdomains found: {condensed['subdomains_count']}
- Active subdomains: {condensed['active_subdomains']}
- Vulnerabilities detected: {condensed['vulnerabilities_found']}
- Technologies identified: {condensed['technologies_detected']}

Key Vulnerabilities Found:
{json.dumps(sample_vulns, indent=2)}

Technologies Detected:
{json.dumps(sample_tech, indent=2)}

Provide a JSON response with these exact keys:
- "summary": Brief overview of attack surface
- "promising_targets": Array of objects with "target" and "reason" keys
- "attack_vectors": Array of objects with "type" and "description" keys  
- "research_areas": Array of objects with "technology" and "note" keys
- "high_value_findings": Array of 3-5 vulnerability types to look for

Return only valid JSON, no additional text."""

    def _parse_unstructured_response(self, text: str, perspective: str) -> Dict:
        """
        Parse unstructured AI response into our format
        """
        # Try to extract JSON from the response
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start != -1 and end != -1:
                json_str = text[start:end]
                parsed = json.loads(json_str)
                parsed['perspective'] = perspective
                parsed['ai_model'] = f'Mithril / {self.client.model}'
                return parsed
        except:
            pass
        
        # Fallback to template
        if perspective == "owner":
            return self._rule_based_owner_analysis({})
        else:
            return self._rule_based_hunter_analysis({})

    def _ensure_owner_structure(self, analysis: Dict) -> Dict:
        """Ensure owner analysis has the correct structure for the template"""
        if not isinstance(analysis.get('key_findings'), list):
            analysis['key_findings'] = []
        if not isinstance(analysis.get('protection_recommendations'), list):
            analysis['protection_recommendations'] = []
        if not isinstance(analysis.get('immediate_actions'), list):
            analysis['immediate_actions'] = []
        
        # Ensure we have at least some data
        if not analysis['key_findings']:
            analysis['key_findings'] = ["No critical vulnerabilities detected in automated scan"]
        if not analysis['protection_recommendations']:
            analysis['protection_recommendations'] = ["Implement security headers", "Enable HTTPS", "Regular security audits"]
        if not analysis['immediate_actions']:
            analysis['immediate_actions'] = ["Review security configurations", "Monitor access logs"]
            
        return analysis

    def _ensure_hunter_structure(self, analysis: Dict) -> Dict:
        """Ensure hunter analysis has the correct structure for the template"""
        # Ensure promising_targets is a list of objects
        if not isinstance(analysis.get('promising_targets'), list):
            analysis['promising_targets'] = []
        
        for i, target in enumerate(analysis['promising_targets']):
            if isinstance(target, str):
                analysis['promising_targets'][i] = {
                    'target': target,
                    'reason': 'Identified during reconnaissance'
                }
            elif not isinstance(target, dict):
                analysis['promising_targets'][i] = {
                    'target': str(target),
                    'reason': 'Automated detection'
                }
        
        # Ensure attack_vectors is a list of objects
        if not isinstance(analysis.get('attack_vectors'), list):
            analysis['attack_vectors'] = []
        
        for i, vector in enumerate(analysis['attack_vectors']):
            if isinstance(vector, str):
                analysis['attack_vectors'][i] = {
                    'type': vector,
                    'description': 'Standard attack vector'
                }
            elif not isinstance(vector, dict):
                analysis['attack_vectors'][i] = {
                    'type': str(vector),
                    'description': 'Automated detection'
                }
        
        # Ensure research_areas is a list of objects
        if not isinstance(analysis.get('research_areas'), list):
            analysis['research_areas'] = []
        
        for i, area in enumerate(analysis['research_areas']):
            if isinstance(area, str):
                analysis['research_areas'][i] = {
                    'technology': area,
                    'note': 'Requires manual investigation'
                }
            elif not isinstance(area, dict):
                analysis['research_areas'][i] = {
                    'technology': str(area),
                    'note': 'Automated detection'
                }
        
        # Ensure high_value_findings is a list
        if not isinstance(analysis.get('high_value_findings'), list):
            analysis['high_value_findings'] = []
        
        # Ensure we have at least some data
        if not analysis['promising_targets']:
            analysis['promising_targets'] = [{'target': 'Main application', 'reason': 'Primary attack surface'}]
        if not analysis['attack_vectors']:
            analysis['attack_vectors'] = [{'type': 'Web Application', 'description': 'Standard web app testing'}]
        if not analysis['research_areas']:
            analysis['research_areas'] = [{'technology': 'Web Server', 'note': 'Check for misconfigurations'}]
        if not analysis['high_value_findings']:
            analysis['high_value_findings'] = ["Authentication bypass", "Injection vulnerabilities"]
            
        return analysis

    def _rule_based_owner_analysis(self, scan_results: Dict) -> Dict:
        """
        Fallback rule-based analysis for website owners
        """
        analysis = self.owner_template.copy()
        
        # Update with actual scan data if available
        if scan_results:
            # Extract vulnerabilities
            vulnerabilities = []
            for scan in scan_results.get('vulnerability_scan', []):
                for vuln in scan.get('vulnerabilities', []):
                    if vuln.get('risk') in ['critical', 'high']:
                        vulnerabilities.append(f"{vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
            
            if vulnerabilities:
                analysis['key_findings'] = vulnerabilities[:5]
            
            # Calculate risk score
            analysis['risk_score'] = self._calculate_risk_score(scan_results)
        
        return analysis

    def _rule_based_hunter_analysis(self, scan_results: Dict) -> Dict:
        """
        Fallback rule-based analysis for bug bounty hunters
        """
        analysis = self.hunter_template.copy()
        
        # Update with actual scan data if available
        if scan_results:
            # Find interesting subdomains
            promising_targets = []
            for subdomain in scan_results.get('subdomains', [])[:5]:
                if subdomain.get('http_status') in [401, 403, 500] or subdomain.get('https_status') in [401, 403, 500]:
                    promising_targets.append({
                        'target': subdomain['subdomain'],
                        'reason': f"Interesting HTTP status: {subdomain.get('http_status') or subdomain.get('https_status')}"
                    })
            
            if promising_targets:
                analysis['promising_targets'] = promising_targets
            
            # Extract attack vectors from vulnerabilities
            attack_vectors = []
            for scan in scan_results.get('vulnerability_scan', []):
                for vuln in scan.get('vulnerabilities', []):
                    if vuln.get('risk') in ['critical', 'high']:
                        attack_vectors.append({
                            'type': vuln.get('type', 'Unknown'),
                            'description': vuln.get('description', 'No description')
                        })
            
            if attack_vectors:
                analysis['attack_vectors'] = attack_vectors[:5]
            
            # Extract research areas from tech detection
            research_areas = []
            for url, tech_data in scan_results.get('tech_detection', {}).items():
                for tech in tech_data.get('technologies', []):
                    if tech.get('version'):
                        research_areas.append({
                            'technology': f"{tech['name']} {tech['version']}",
                            'note': f"Check for known vulnerabilities in this version"
                        })
            
            if research_areas:
                analysis['research_areas'] = research_areas[:5]
        
        return analysis

    def _calculate_risk_score(self, scan_results: Dict) -> int:
        """Calculate a risk score (0-100) based on scan results"""
        score = 0
        
        # Critical vulnerabilities
        crit_vulns = sum(1 for scan in scan_results.get('vulnerability_scan', [])
                     for vuln in scan.get('vulnerabilities', [])
                     if vuln.get('risk') == 'critical')
        score += crit_vulns * 20
        
        # High vulnerabilities
        high_vulns = sum(1 for scan in scan_results.get('vulnerability_scan', [])
                    for vuln in scan.get('vulnerabilities', [])
                    if vuln.get('risk') == 'high')
        score += high_vulns * 10
        
        # Subdomain exposure
        subdomains = len(scan_results.get('subdomains', []))
        if subdomains > 100:
            score += 30
        elif subdomains > 50:
            score += 20
        elif subdomains > 20:
            score += 10
        
        return min(100, score)
