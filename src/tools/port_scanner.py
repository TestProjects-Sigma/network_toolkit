import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from ..utils.logger import get_logger

logger = get_logger("port_scanner_tool")

# Common service names for well-known ports
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

class ScanResult:
    """Class to store port scan results"""
    def __init__(self):
        self.host = ""
        self.ip_address = ""
        self.open_ports = []  # List of (port, service) tuples
        self.closed_ports = []  # List of (port, service) tuples
        self.error = None
        self.progress = 0
        self.current_port = 0
        self.status = "Not started"
        self.finished = False
        self.start_time = 0
        self.end_time = 0
        self.total_ports = 0

def get_service_name(port):
    """Get the service name for a port number"""
    return PORT_SERVICES.get(port, "Unknown")

def scan_port(host, port, timeout=1):
    """
    Scan a single port.
    
    Args:
        host (str): Host to scan
        port (int): Port to scan
        timeout (float): Connection timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False

def scan_ports(host, ports, progress_callback=None):
    """
    Scan multiple ports on a host.
    
    Args:
        host (str): Host to scan
        ports (list): List of ports to scan
        progress_callback (function): Callback to report progress
        
    Returns:
        ScanResult: Scan results
    """
    result = ScanResult()
    result.host = host
    result.total_ports = len(ports)
    result.start_time = time.time()
    
    def update_progress(status, progress, current_port=None):
        result.status = status
        result.progress = progress
        if current_port is not None:
            result.current_port = current_port
        if progress_callback:
            progress_callback(result)
    
    def run_scan():
        try:
            # Get IP address
            update_progress("Resolving hostname...", 0)
            try:
                result.ip_address = socket.gethostbyname(host)
                logger.info(f"Resolved {host} to {result.ip_address}")
            except socket.gaierror:
                result.error = f"Could not resolve hostname: {host}"
                logger.error(result.error)
                update_progress(f"Error: {result.error}", 0)
                result.finished = True
                return
            
            # Prepare for scanning
            update_progress(f"Starting scan of {len(ports)} ports on {host} ({result.ip_address})", 5)
            max_workers = min(50, len(ports))  # Limit max concurrent threads
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all scan tasks
                future_to_port = {
                    executor.submit(scan_port, result.ip_address, port, 1): port for port in ports
                }
                
                # Process results as they complete
                completed = 0
                for future in future_to_port:
                    port = future_to_port[future]
                    service = get_service_name(port)
                    
                    try:
                        is_open = future.result()
                        if is_open:
                            result.open_ports.append((port, service))
                            logger.info(f"Port {port} ({service}) is open on {host}")
                        else:
                            result.closed_ports.append((port, service))
                    except Exception as e:
                        logger.error(f"Error scanning port {port}: {e}")
                        result.closed_ports.append((port, service))
                    
                    # Update progress
                    completed += 1
                    progress = 5 + (95 * completed / len(ports))
                    update_progress(f"Scanning... ({completed}/{len(ports)})", progress, port)
            
            # Scan completed
            result.end_time = time.time()
            duration = result.end_time - result.start_time
            update_progress(f"Scan completed in {duration:.2f} seconds", 100)
            logger.info(f"Port scan of {host} completed in {duration:.2f} seconds. " 
                       f"Found {len(result.open_ports)} open ports.")
            
        except Exception as e:
            result.error = f"Error during port scan: {str(e)}"
            logger.error(result.error)
            update_progress(f"Error: {result.error}", 0)
        
        finally:
            result.finished = True
            if progress_callback:
                progress_callback(result)
    
    # Create and start the scan thread
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.daemon = True
    scan_thread.start()
    
    return result

def get_common_ports():
    """Get a list of common ports to scan with descriptions"""
    return [
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (8080, "HTTP-Proxy")
    ]

def format_scan_results(result):
    """Format port scan results for display"""
    if result.error:
        return f"PORT SCAN ERROR:\n{'-' * 60}\n{result.error}"
    
    output = f"PORT SCAN RESULTS: {result.host} ({result.ip_address})\n{'-' * 60}\n"
    
    # Scan summary
    scan_time = result.end_time - result.start_time
    output += f"Scan completed in {scan_time:.2f} seconds\n"
    output += f"Scanned {result.total_ports} ports\n"
    output += f"Open ports: {len(result.open_ports)}\n"
    output += f"Closed ports: {len(result.closed_ports)}\n\n"
    
    if result.open_ports:
        output += f"OPEN PORTS:\n{'-' * 60}\n"
        output += f"{'PORT':<10} {'SERVICE':<20} {'STATUS':<10}\n"
        output += f"{'-' * 40}\n"
        
        # Sort open ports numerically
        for port, service in sorted(result.open_ports):
            output += f"{port:<10} {service:<20} {'Open':<10}\n"
    else:
        output += "No open ports found.\n"
    
    return output