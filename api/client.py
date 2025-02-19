import requests
import json

class HybridAnalysisClient:
    def __init__(self, api_key, base_url, logger):
        self.api_key = api_key
        self.base_url = base_url
        self.log = logger  # Use same name as service for consistency
        self.session = requests.Session()
        self.headers = {
            'User-agent': 'Assemblyline v4',
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',  # Required for form data
            'api-key': api_key
        }

    def test_connection(self):
        """Test the API connection and key validity"""
        try:
            self.log.info("Testing Hybrid Analysis API connection")
            response = self.session.get(
                f"{self.base_url}/key/current",
                headers=self.headers
            )
            
            if response.status_code != 200:
                error_msg = f"Failed to validate API key: {response.text}"
                self.log.error(error_msg, extra={
                    'status_code': response.status_code,
                    'response': response.text
                })
                raise ValueError(error_msg)
            
            self.log.info("Successfully validated API key")
            
        except Exception as e:
            error_msg = f"Failed to validate API key: {str(e)}"
            self.log.error(error_msg, exc_info=True)
            raise

    def check_existing_analysis(self, sha256):
        """Check if file has existing analysis using /search/hash endpoint"""
        try:
            self.log.info("Checking for existing analysis", extra={'sha256': sha256})
            
            # Using /search/hash endpoint with POST and form data
            data = {'hash': sha256}
            response = self.session.post(
                f"{self.base_url}/search/hash",
                headers=self.headers,
                data=data
            )
            
            self.log.info("API Response received", extra={
                'status_code': response.status_code,
                'sha256': sha256
            })
            
            if response.status_code == 200:
                results = response.json()
                if isinstance(results, list) and results:
                    # Find completed analysis only
                    completed_results = [r for r in results if r.get('state') != 'IN_PROGRESS']
                    if completed_results:
                        # Find the most detailed analysis result
                        best_result = max(completed_results, key=lambda x: (
                            x.get('total_signatures', 0),  # Prefer results with more signatures
                            x.get('threat_score', 0),      # Then higher threat scores
                            x.get('analysis_start_time', '') # Then most recent
                        ))
                        
                        self.log.info("Found existing analysis", extra={
                            'sha256': sha256,
                            'analysis_count': len(completed_results),
                            'selected_environment': best_result.get('environment_description'),
                            'total_signatures': best_result.get('total_signatures'),
                            'threat_score': best_result.get('threat_score'),
                            'verdict': best_result.get('verdict')
                        })
                        return best_result
            
            self.log.info("No existing analysis found", extra={'sha256': sha256})
            return None
            
        except Exception as e:
            self.log.error("Error checking existing analysis", extra={
                'sha256': sha256,
                'error': str(e)
            }, exc_info=True)
            return None

    def check_in_progress_analysis(self, sha256):
        """Check if file is currently being analyzed"""
        try:
            self.log.info("Checking for in-progress analysis", extra={'sha256': sha256})
            response = self.session.get(
                f"{self.base_url}/state/{sha256}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                state = response.json()
                if state.get('state') == 'IN_PROGRESS':
                    self.log.info("Analysis in progress", extra={'sha256': sha256})
                    return True
            
            self.log.info("No in-progress analysis found", extra={'sha256': sha256})
            return False
            
        except Exception as e:
            self.log.error("Error checking in-progress analysis", extra={
                'sha256': sha256,
                'error': str(e)
            }, exc_info=True)
            return False

    def submit_file(self, file_path, file_name, environment_id=None, experimental_anti_evasion=None, network_settings=None):
        """Submit a file for analysis"""
        try:
            self.log.info("Submitting file for analysis", extra={
                'file_name': file_name,
                'environment_id': environment_id,
                'experimental_anti_evasion': experimental_anti_evasion,
                'network_settings': network_settings
            })
            
            with open(file_path, 'rb') as f:
                # For file upload, we need to use multipart/form-data
                headers = {k: v for k, v in self.headers.items() if k != 'Content-Type'}
                files = {'file': (file_name, f)}
                data = {
                    'environment_id': environment_id or 160,  # Default to Windows 10 64 bit
                    'allow_community_access': True,
                    'no_share_third_party': True
                }

                # Add optional parameters if provided
                if experimental_anti_evasion is not None:
                    data['experimental_anti_evasion'] = experimental_anti_evasion
                if network_settings:
                    data['network_settings'] = network_settings
                
                submit_response = self.session.post(
                    f"{self.base_url}/submit/file",
                    headers=headers,
                    files=files,
                    data=data
                )
                
                if submit_response.status_code not in [200, 201]:
                    error_msg = f"File submission failed: {submit_response.text}"
                    self.log.error(error_msg, extra={
                        'status_code': submit_response.status_code,
                        'response': submit_response.text,
                        'file_name': file_name
                    })
                    raise ValueError(error_msg)
                
                response_data = submit_response.json()
                self.log.info("File submitted successfully", extra={
                    'job_id': response_data.get('job_id'),
                    'file_name': file_name
                })
                return response_data
            
        except Exception as e:
            self.log.error("Error submitting file", extra={
                'file_name': file_name,
                'error': str(e)
            }, exc_info=True)
            raise

    def get_report(self, job_id, sha256):
        """Get analysis report"""
        try:
            # If we have a job_id, try to get the report by job_id first
            if job_id:
                self.log.info("Retrieving report by job ID", extra={'job_id': job_id})
                response = self.session.get(
                    f"{self.base_url}/report/{job_id}/summary",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    summary = response.json()
                    if summary.get('verdict'):  # If we have a complete result
                        self.log.info("Retrieved analysis results by job ID", extra={
                            'verdict': summary.get('verdict'),
                            'job_id': job_id
                        })
                        return summary
            
            # If no job_id or job_id report not ready, and sha256 is provided, try by hash
            if sha256:
                self.log.info("Retrieving analysis results by hash", extra={'sha256': sha256})
                data = {'hash': sha256}
                response = self.session.post(
                    f"{self.base_url}/search/hash",
                    headers=self.headers,
                    data=data
                )
            
                if response.status_code == 200:
                    results = response.json()
                    if isinstance(results, list) and results:
                        # Find completed analysis only
                        completed_results = [r for r in results if r.get('state') != 'IN_PROGRESS']
                        if completed_results:
                            # Find the most detailed analysis result
                            best_result = max(completed_results, key=lambda x: (
                                x.get('total_signatures', 0),  # Prefer results with more signatures
                                x.get('threat_score', 0),      # Then higher threat scores
                                x.get('analysis_start_time', '') # Then most recent
                            ))
                            
                            self.log.info("Retrieved analysis results by hash", extra={
                                'verdict': best_result.get('verdict'),
                                'threat_score': best_result.get('threat_score'),
                                'total_signatures': best_result.get('total_signatures'),
                                'environment': best_result.get('environment_description'),
                                'sha256': sha256
                            })
                            return best_result
            
            return None
            
        except Exception as e:
            self.log.error("Error getting report", extra={
                'job_id': job_id,
                'sha256': sha256,
                'error': str(e)
            }, exc_info=True)
            raise

    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()
            self.log.info("API session closed")