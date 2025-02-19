import logging
import os
import sys
import tempfile

def setup_logging(service_instance, config):
    """Setup logging based on configuration"""
    # Get debug logging configuration
    debug_enabled = config.get("enable_debug_logging", {}).get("value", False)
    
    # Always start with the standard service logger
    service_log = service_instance.log
    
    if not debug_enabled:
        # When debug is disabled, only use INFO level logging
        service_log.setLevel(logging.INFO)
        # Remove any existing handlers that might be set to DEBUG
        for handler in service_log.handlers:
            handler.setLevel(logging.INFO)
        return service_log
        
    # Debug logging setup
    log_path = os.path.join(tempfile.gettempdir(), 'hybrid_analysis.log')
    
    try:
        debug_logger = logging.getLogger('hybrid_analysis_debug')
        debug_logger.setLevel(logging.DEBUG)
        
        debug_logger.handlers = []
        
        file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        stdout_handler.setFormatter(formatter)
        
        debug_logger.addHandler(file_handler)
        debug_logger.addHandler(stdout_handler)
        debug_logger.propagate = False
        
        return debug_logger
            
    except Exception as e:
        service_instance.log.warning(f"Failed to setup debug logging: {str(e)}")
        return service_instance.log