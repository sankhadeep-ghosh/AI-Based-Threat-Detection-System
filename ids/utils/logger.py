"""
Logger utility module - provides centralized logging configuration
for the entire IDS system with rotation and multiple handlers.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10485760,
    backup_count: int = 5,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Configure and return a logger instance with file and console handlers.
    
    Args:
        name: Logger name (use __name__ from caller)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        max_bytes: Max size before rotation (default 10MB)
        backup_count: Number of backup files to keep
        format_string: Custom log format (optional)
        
    Returns:
        Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Prevent duplicate handlers if logger already configured
    if logger.handlers:
        return logger
    
    # Format
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(format_string)
    
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File Handler (with rotation)
    if log_file:
        try:
            # Ensure directory exists
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to setup file handler for {log_file}: {e}")
    
    return logger

# Example usage
if __name__ == "__main__":
    log = setup_logger(__name__, level="DEBUG", log_file="logs/test.log")
    log.debug("Debug message")
    log.info("Info message")
    log.warning("Warning message")
    log.error("Error message")
