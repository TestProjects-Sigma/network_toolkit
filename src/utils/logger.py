import logging
import os
from datetime import datetime

def setup_logger(name, log_file, level=logging.INFO):
    """
    Set up a logger with file and console handlers.
    
    Args:
        name (str): Logger name
        log_file (str): Path to log file
        level (int): Logging level
        
    Returns:
        logging.Logger: Configured logger
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name):
    """
    Get a logger by name, or create a new one if it doesn't exist.
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Requested logger
    """
    logger = logging.getLogger(name)
    
    # If logger doesn't have handlers, set it up
    if not logger.handlers:
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Create log file name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = f"logs/{name}_{timestamp}.log"
        
        # Set up logger
        logger = setup_logger(name, log_file)
    
    return logger
