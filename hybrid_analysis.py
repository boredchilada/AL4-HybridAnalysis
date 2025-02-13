from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, TableRow, BODY_FORMAT
import time
import requests
import logging
import os
import json
import tempfile
import sys

class HybridAnalysis(ServiceBase):
    def __init__(self, config=None):
        super(HybridAnalysis, self).__init__(config)
        self.api_key = None
        self.base_url = None
        self.session = None
        self.headers = {
            'User-agent': 'Assemblyline v4',
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        self.setup_logging()

    def setup_logging(self):
        """Setup detailed logging to file"""
        log_path = os.path.join(tempfile.gettempdir(), 'hybrid_analysis.log')
        
        try:
            self.debug_log = logging.getLogger('hybrid_analysis_debug')
            self.debug_log.setLevel(logging.DEBUG)
            
            self.debug_log.handlers = []
            
            file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setLevel(logging.DEBUG)
            
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            stdout_handler.setFormatter(formatter)
            
            self.debug_log.addHandler(file_handler)
            self.debug_log.addHandler(stdout_handler)
            
            self.debug_log.propagate = False
            
            self.debug_log.info("="*50)
            self.debug_log.info(f"Logging initialized. Log file: {log_path}")
            self.debug_log.info("="*50)
            
            for handler in self.debug_log.handlers:
                handler.flush()
                
        except Exception as e:
            self.log.warning(f"Failed to setup debug logging: {str(e)}")
            self.debug_log = self.log  

    def start(self):
        """Service initialization"""
        self.log.info("Starting Hybrid Analysis Service")
        self.debug_log.info("Starting Hybrid Analysis Service")
        
        api_config = self.config.get("api_key", {})
        base_url_config = self.config.get("base_url", {})
        
        self.api_key = api_config.get('value') if isinstance(api_config, dict) else api_config
        self.base_url = base_url_config.get('value', "https://www.hybrid-analysis.com/api/v2") if isinstance(base_url_config, dict) else base_url_config
        
        self.debug_log.info(f"Configuration loaded - Base URL: {self.base_url}")
        
        if not self.api_key:
            self.debug_log.error("Missing API key in service configuration")
            raise ValueError("Missing API key in service configuration")
            
        self.session = requests.Session()
        self.headers['api-key'] = self.api_key
        
        self.test_api_connection()
        
        for handler in self.debug_log.handlers:
            handler.flush()

    def stop(self):
        """Service cleanup"""
        self.log.info("Stopping Hybrid Analysis Service")
        self.debug_log.info("Stopping Hybrid Analysis Service")
        if self.session:
            self.session.close()
            
        # Force flush logs before stopping
        for handler in self.debug_log.handlers:
            handler.flush()

    def test_api_connection(self):
        """Test the API connection and key validity"""
        try:
            self.debug_log.info("Testing API connection...")
            response = self.session.get(
                f"{self.base_url}/key/current",
                headers=self.headers
            )
            
            self.debug_log.info(f"API test response status: {response.status_code}")
            self.debug_log.debug(f"API test response content: {response.text}")
            
            if response.status_code != 200:
                error_msg = f"Failed to validate API key: {response.text}"
                self.debug_log.error(error_msg)
                raise ValueError(error_msg)
            
            self.log.info("Successfully validated API key")
            self.debug_log.info("Successfully validated API key")
            
            for handler in self.debug_log.handlers:
                handler.flush()
            
        except Exception as e:
            error_msg = f"Failed to validate API key: {str(e)}"
            self.log.error(error_msg)
            self.debug_log.error(error_msg)
            
            for handler in self.debug_log.handlers:
                handler.flush()
                
            raise

    def execute(self, request):
        """Main execution"""
        result = Result()
        try:
            self.debug_log.info(f"Processing file: {request.file_name}")
            
            files = {'file': (request.file_name, open(request.file_path, 'rb'))}
            data = {
                'environment_id': 120,  # Windows 10
                'allow_community_access': True,
                'no_share_third_party': True
            }
            
            self.debug_log.info("Submitting file to Hybrid Analysis...")
            self.debug_log.debug(f"Submission data: {json.dumps(data)}")
            
            submit_response = self.session.post(
                f"{self.base_url}/submit/file",
                headers={k: v for k, v in self.headers.items() if k != 'Content-Type'},
                files=files,
                data=data
            )
            
            self.debug_log.info(f"Submit response status: {submit_response.status_code}")
            self.debug_log.debug(f"Submit response content: {submit_response.text}")
            
            for handler in self.debug_log.handlers:
                handler.flush()
            
            if submit_response.status_code not in [200, 201]:
                error_msg = f"File submission failed: {submit_response.text}"
                self.debug_log.error(error_msg)
                raise ValueError(error_msg)
            
            submission_data = submit_response.json()
            sha256 = submission_data.get('sha256')
            job_id = submission_data.get('job_id')
            
            if not sha256:
                error_msg = "No SHA256 received from submission"
                self.debug_log.error(error_msg)
                raise ValueError(error_msg)
            
            self.debug_log.info(f"File submitted successfully. SHA256: {sha256}, Job ID: {job_id}")
            
            max_attempts = 30
            for attempt in range(max_attempts):
                self.debug_log.info(f"Polling attempt {attempt + 1}/{max_attempts}")
                
                overview_response = self.session.get(
                    f"{self.base_url}/report/{job_id}/summary",
                    headers=self.headers
                )
                
                self.debug_log.debug(f"Overview response status: {overview_response.status_code}")
                self.debug_log.debug(f"Overview response content: {overview_response.text}")
                
                for handler in self.debug_log.handlers:
                    handler.flush()
                
                if overview_response.status_code == 404:
                    overview_response = self.session.get(
                        f"{self.base_url}/overview/{sha256}",
                        headers=self.headers
                    )
                    
                    self.debug_log.debug(f"SHA256 overview response status: {overview_response.status_code}")
                    self.debug_log.debug(f"SHA256 overview response content: {overview_response.text}")
                
                if overview_response.status_code not in [200, 201]:
                    time.sleep(10)
                    continue
                
                overview = overview_response.json()
                verdict = overview.get('verdict')
                
                if verdict:
                    self.debug_log.info(f"Analysis complete. Verdict: {verdict}")
                    
                    main_section = ResultSection("Hybrid Analysis Results")
                    self.debug_log.info("Created main result section")
                    
                    summary_section = ResultSection("Analysis Summary")
                    summary_section.add_line(f"Verdict: {verdict}")
                    if overview.get('threat_score'):
                        threat_score = int(overview['threat_score'])
                        summary_section.add_line(f"Threat Score: {threat_score}")
                        if threat_score >= 100:
                            self.debug_log.info(f"Setting heuristic 1 for high threat score: {threat_score}")
                            summary_section.set_heuristic(1)
                    if overview.get('threat_level'):
                        summary_section.add_line(f"Threat Level: {overview['threat_level']}")
                    if overview.get('vx_family'):
                        summary_section.add_line(f"Malware Family: {overview['vx_family']}")
                        summary_section.add_tag('attribution.family', overview['vx_family'])
                    
                    main_section.add_subsection(summary_section)
                    self.debug_log.info("Added summary section to main section")
                    
                    if overview.get('signatures'):
                        behavior_section = ResultTableSection("Behavioral Analysis")
                        behavior_section.set_column_order([
                            "name",
                            "description",
                            "threat_level",
                            "category",
                            "attack_id"
                        ])
                        
                        highest_threat_level = 0
                        
                        for sig in overview['signatures']:
                            row = TableRow({
                                "name": sig.get('name', ''),
                                "description": sig.get('description', ''),
                                "threat_level": f"{sig.get('threat_level_human', '')} ({sig.get('threat_level', '')})",
                                "category": sig.get('category', ''),
                                "attack_id": sig.get('attck_id', '')
                            })
                            behavior_section.add_row(row)
                            
                            if sig.get('attck_id'):
                                behavior_section.add_tag('technique.id', sig['attck_id'])
                            
                            threat_level = sig.get('threat_level', 0)
                            highest_threat_level = max(highest_threat_level, threat_level)
                        
                        if highest_threat_level >= 2:  # malicious
                            self.debug_log.info(f"Setting heuristic 2 for malicious behavior (threat level: {highest_threat_level})")
                            behavior_section.set_heuristic(2)
                        elif highest_threat_level == 1:  # suspicious
                            self.debug_log.info(f"Setting heuristic 3 for suspicious behavior (threat level: {highest_threat_level})")
                            behavior_section.set_heuristic(3)
                            
                        main_section.add_subsection(behavior_section)
                        self.debug_log.info("Added behavior section to main section")
                    
                    self._add_process_section(overview, main_section)
                    self._add_network_section(overview, main_section)
                    self._add_file_section(overview, main_section)
                    self._add_registry_section(overview, main_section)
                    
                    result.add_section(main_section)
                    self.debug_log.info("Added main section to result")
                    
                    self.debug_log.info(f"Result sections count: {len(result.sections)}")
                    for section in result.sections:
                        self.debug_log.info(f"Section title: {section.title_text}, Subsections: {len(section.subsections)}")
                    
                    break
                    
                time.sleep(10)
            
        except Exception as e:
            error_msg = f"Error in analysis: {str(e)}"
            self.log.error(error_msg)
            self.debug_log.error(error_msg)
            error_section = ResultSection("Service Error", body=str(e))
            result.add_section(error_section)
            
            for handler in self.debug_log.handlers:
                handler.flush()
            
        self.debug_log.info(f"Final result sections count: {len(result.sections)}")
        
        request.result = result
        self.debug_log.info("Set result on request object")
        
        return result

    def _add_process_section(self, overview, main_section):
        """Add process activity section if available"""
        if overview.get('processes'):
            self.debug_log.info("Adding process activity section")
            process_section = ResultTableSection("Process Activity")
            process_section.set_column_order([
                "process_name",
                "command_line",
                "pid"
            ])
            
            for process in overview['processes']:
                row = TableRow({
                    "process_name": process.get('name', ''),
                    "command_line": process.get('command_line', ''),
                    "pid": str(process.get('pid', ''))
                })
                process_section.add_row(row)
                
                if process.get('name'):
                    process_section.add_tag('dynamic.process.name', process['name'])
                if process.get('command_line'):
                    process_section.add_tag('dynamic.process.command_line', process['command_line'])
                    
            main_section.add_subsection(process_section)

    def _add_network_section(self, overview, main_section):
        """Add network activity section if available"""
        if overview.get('network_activity'):
            self.debug_log.info("Adding network activity section")
            network_section = ResultTableSection("Network Activity")
            network_section.set_column_order([
                "destination",
                "port",
                "protocol",
                "domain"
            ])
            
            for activity in overview['network_activity']:
                row = TableRow({
                    "destination": activity.get('destination_ip', ''),
                    "port": str(activity.get('destination_port', '')),
                    "protocol": activity.get('protocol', ''),
                    "domain": activity.get('domain', '')
                })
                network_section.add_row(row)
                
                if activity.get('destination_ip'):
                    network_section.add_tag('network.static.ip', activity['destination_ip'])
                if activity.get('destination_port'):
                    network_section.add_tag('network.port', str(activity['destination_port']))
                if activity.get('domain'):
                    network_section.add_tag('network.static.domain', activity['domain'])
                    
            main_section.add_subsection(network_section)

    def _add_file_section(self, overview, main_section):
        """Add file activity section if available"""
        if overview.get('file_activity'):
            self.debug_log.info("Adding file activity section")
            file_section = ResultTableSection("File Activity")
            file_section.set_column_order([
                "path",
                "action",
                "sha256"
            ])
            
            for activity in overview['file_activity']:
                row = TableRow({
                    "path": activity.get('path', ''),
                    "action": activity.get('action', ''),
                    "sha256": activity.get('sha256', '')
                })
                file_section.add_row(row)
                
                if activity.get('sha256'):
                    file_section.add_tag('file.sha256', activity['sha256'])
                if activity.get('path'):
                    file_section.add_tag('dynamic.file.path', activity['path'])
                    
            main_section.add_subsection(file_section)

    def _add_registry_section(self, overview, main_section):
        """Add registry activity section if available"""
        if overview.get('registry_activity'):
            self.debug_log.info("Adding registry activity section")
            registry_section = ResultTableSection("Registry Activity")
            registry_section.set_column_order([
                "key",
                "value",
                "action"
            ])
            
            for activity in overview['registry_activity']:
                row = TableRow({
                    "key": activity.get('key', ''),
                    "value": activity.get('value', ''),
                    "action": activity.get('action', '')
                })
                registry_section.add_row(row)
                
                if activity.get('key'):
                    registry_section.add_tag('dynamic.registry.key', activity['key'])
                    
            main_section.add_subsection(registry_section)
