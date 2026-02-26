import time
import hashlib
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline.common.exceptions import RecoverableError, NonRecoverableError
from assemblyline_v4_service.common.result import Result, ResultSection

from utils.logging_setup import setup_logging
from api.client import HybridAnalysisClient
from models.result_processor import ResultProcessor

class HybridAnalysisService(ServiceBase):
    def __init__(self, config=None):
        super(HybridAnalysisService, self).__init__(config)
        self.api_key = None
        self.base_url = None
        self.client = None
        self.result_processor = None
        self.log = setup_logging(self, config)

    def start(self):
        self.log.info("Starting Hybrid Analysis Service", extra={
            'service_name': self.service_attributes.name,
            'service_version': self.service_attributes.version
        })
        
        api_config = self.config.get("api_key", {})
        base_url_config = self.config.get("base_url", {})
        
        self.api_key = api_config.get('value') if isinstance(api_config, dict) else api_config
        self.base_url = base_url_config.get('value', "https://www.hybrid-analysis.com/api/v2") if isinstance(base_url_config, dict) else base_url_config
        
        if not self.api_key:
            self.log.error("Missing API key in service configuration", extra={
                'config_keys': list(self.config.keys())
            })
            raise NonRecoverableError("Missing API key in service configuration")
        
        self.log.info("Initializing API client", extra={'base_url': self.base_url})
        self.client = HybridAnalysisClient(self.api_key, self.base_url, self.log)
        self.client.test_connection()
        
        self.log.info("Initializing result processor")
        self.result_processor = ResultProcessor(self)
        self.log.info("Hybrid Analysis Service initialized successfully", extra={
            'base_url': self.base_url,
            'client_initialized': self.client is not None,
            'processor_initialized': self.result_processor is not None
        })

    def stop(self):
        self.log.info("Stopping Hybrid Analysis Service")
        if self.client:
            self.log.info("Closing API client connection")
            self.client.close()
        self.log.info("Hybrid Analysis Service stopped successfully")

    def execute(self, request):
        result = Result()
        start_time = time.time()
        
        try:
            self.log.info(f"Processing file: {request.file_name}", extra={
                'file_size': request.file_size,
                'file_type': request.file_type
            })
            
            with open(request.file_path, 'rb') as f:
                file_data = f.read()
                sha256 = hashlib.sha256(file_data).hexdigest()
            
            self.log.debug("File hash calculated", extra={
                'sha256': sha256,
                'file_size': len(file_data)
            })

            force_resubmit = request.get_param('force_resubmit')
            environment_id = request.get_param('environment_id')
            experimental_anti_evasion = request.get_param('experimental_anti_evasion')
            network_settings = request.get_param('network_settings')

            self.log.debug("Submission parameters", extra={
                'force_resubmit': force_resubmit,
                'environment_id': environment_id,
                'experimental_anti_evasion': experimental_anti_evasion,
                'network_settings': network_settings
            })
            
            if not force_resubmit:
                existing_analysis = self.client.check_existing_analysis(sha256)
                if existing_analysis:
                    self.log.info(f"Found existing analysis for {request.file_name}", extra={
                        'sha256': sha256,
                        'analysis_id': existing_analysis.get('analysis_id')
                    })
                    main_section = self.result_processor.create_main_section(existing_analysis)
                    result.add_section(main_section)
                    request.result = result
                    return result
                
                if self.client.check_in_progress_analysis(sha256):
                    self.log.info(f"Analysis in progress for {request.file_name}", extra={'sha256': sha256})
                    max_attempts = 30
                    for attempt in range(max_attempts):
                        self.log.debug(f"Polling attempt {attempt + 1}/{max_attempts}", extra={
                            'sha256': sha256,
                            'elapsed_time': time.time() - start_time
                        })
                        existing = self.client.check_existing_analysis(sha256)
                        if existing and existing.get('verdict'):
                            self.log.info(f"Analysis complete for {request.file_name}", extra={
                                'verdict': existing['verdict'],
                                'attempts': attempt + 1
                            })
                            main_section = self.result_processor.create_main_section(existing)
                            result.add_section(main_section)
                            break
                            
                        time.sleep(10)
                    
                    if not result.sections:
                        self.log.warning(f"Max polling attempts reached for {request.file_name}", extra={
                            'max_attempts': max_attempts,
                            'elapsed_time': time.time() - start_time
                        })
                        raise RecoverableError("Analysis timeout. Max polling attempts reached.")
                    
                    request.result = result
                    return result
            
            self.log.info(f"Submitting {request.file_name} for new analysis", extra={'sha256': sha256})
            submission_data = self.client.submit_file(
                file_path=request.file_path,
                file_name=request.file_name,
                environment_id=environment_id,
                experimental_anti_evasion=experimental_anti_evasion,
                network_settings=network_settings
            )
            
            job_id = submission_data.get('job_id')
            if not job_id:
                error_msg = "No job ID received from submission"
                self.log.error(error_msg, extra={'submission_data': submission_data})
                raise NonRecoverableError(error_msg)
            
            self.log.info(f"File {request.file_name} submitted successfully", extra={
                'job_id': job_id,
                'sha256': sha256
            })
            
            max_attempts = 30
            for attempt in range(max_attempts):
                self.log.debug(f"Polling for results (attempt {attempt + 1}/{max_attempts})", extra={
                    'job_id': job_id,
                    'elapsed_time': time.time() - start_time
                })
                overview = self.client.get_report(job_id, None if force_resubmit else sha256)
                if overview and overview.get('verdict'):
                    self.log.info(f"Analysis complete for {request.file_name}", extra={
                        'verdict': overview['verdict'],
                        'attempts': attempt + 1,
                        'job_id': job_id
                    })
                    main_section = self.result_processor.create_main_section(overview)
                    result.add_section(main_section)
                    break
                    
                time.sleep(10)
            
            if not result.sections:
                self.log.warning(f"Max polling attempts reached for {request.file_name}", extra={
                    'max_attempts': max_attempts,
                    'job_id': job_id,
                    'elapsed_time': time.time() - start_time
                })
                raise RecoverableError("Analysis timeout. Max polling attempts reached.")
            
        except (RecoverableError, NonRecoverableError):
            raise
        except Exception as e:
            error_msg = f"Error analyzing {request.file_name}: {str(e)}"
            self.log.error(error_msg, extra={
                'error_type': type(e).__name__,
                'elapsed_time': time.time() - start_time
            }, exc_info=True)
            raise NonRecoverableError(error_msg)
        
        request.result = result
        self.log.info(f"Analysis completed for {request.file_name}", extra={
            'execution_time': time.time() - start_time,
            'sections_count': len(result.sections)
        })
        return result