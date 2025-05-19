import speedtest
import time
import threading
from ..utils.logger import get_logger

logger = get_logger("speedtest_tool")

class SpeedTestResult:
    """Class to store speed test results"""
    def __init__(self):
        self.download = 0
        self.upload = 0
        self.ping = 0
        self.server_name = ""
        self.server_country = ""
        self.client_ip = ""
        self.client_isp = ""
        self.status = "Not started"
        self.progress = 0
        self.error = None
        self.finished = False
        
def run_speed_test(progress_callback=None):
    """
    Run a network speed test.
    
    Args:
        progress_callback: Optional callback function to report progress
        
    Returns:
        SpeedTestResult: Speed test results
    """
    result = SpeedTestResult()
    
    def update_progress(status, progress):
        result.status = status
        result.progress = progress
        if progress_callback:
            progress_callback(result)
            
    def run_test():
        try:
            logger.info("Starting speed test")
            update_progress("Initializing...", 0)
            
            # Create speedtest object
            st = speedtest.Speedtest()
            
            # Get client info
            update_progress("Getting client information...", 10)
            client_info = st.get_config()
            result.client_ip = client_info['client']['ip']
            result.client_isp = client_info['client']['isp']
            
            # Get best server
            update_progress("Finding best server...", 20)
            st.get_best_server()
            if hasattr(st, 'best') and st.best:
                result.server_name = f"{st.best['host']} ({st.best['name']})"
                result.server_country = st.best['country']
            
            # Test download speed
            update_progress("Testing download speed...", 30)
            download_speed = st.download()
            result.download = download_speed / 1_000_000  # Convert to Mbps
            update_progress("Download test completed", 60)
            
            # Test upload speed
            update_progress("Testing upload speed...", 70)
            upload_speed = st.upload()
            result.upload = upload_speed / 1_000_000  # Convert to Mbps
            update_progress("Upload test completed", 90)
            
            # Test ping (latency)
            update_progress("Testing latency...", 95)
            result.ping = st.results.ping
            
            # Test completed
            update_progress("Test completed", 100)
            logger.info("Speed test completed successfully")
            
        except Exception as e:
            error_msg = f"Error during speed test: {str(e)}"
            logger.error(error_msg)
            result.error = error_msg
            update_progress(f"Error: {str(e)}", 0)
        
        finally:
            result.finished = True
            if progress_callback:
                progress_callback(result)
    
    # Create and start the test thread
    test_thread = threading.Thread(target=run_test)
    test_thread.daemon = True
    test_thread.start()
    
    return result

def format_speed_test_results(result):
    """Format speed test results for display"""
    if result.error:
        return f"SPEED TEST ERROR:\n{'-' * 60}\n{result.error}"
    
    output = f"SPEED TEST RESULTS:\n{'-' * 60}\n"
    
    output += f"Download Speed: {result.download:.2f} Mbps\n"
    output += f"Upload Speed: {result.upload:.2f} Mbps\n"
    output += f"Ping (Latency): {result.ping:.2f} ms\n\n"
    
    output += f"Server: {result.server_name}\n"
    output += f"Server Country: {result.server_country}\n\n"
    
    output += f"Client IP: {result.client_ip}\n"
    output += f"ISP: {result.client_isp}\n"
    
    # Add a simple rating
    download_rating = "Excellent" if result.download > 100 else "Good" if result.download > 30 else "Average" if result.download > 10 else "Poor"
    upload_rating = "Excellent" if result.upload > 50 else "Good" if result.upload > 15 else "Average" if result.upload > 5 else "Poor"
    ping_rating = "Excellent" if result.ping < 20 else "Good" if result.ping < 50 else "Average" if result.ping < 100 else "Poor"
    
    output += f"\nRATINGS:\n"
    output += f"Download: {download_rating}\n"
    output += f"Upload: {upload_rating}\n"
    output += f"Latency: {ping_rating}\n"
    
    return output