import subprocess
import platform
import re
import socket
from ..utils.logger import get_logger

logger = get_logger("traceroute_tool")

def traceroute(host, max_hops=30, timeout=2):
    """
    Perform a traceroute to the specified host.
    
    Args:
        host (str): Hostname or IP address to trace
        max_hops (int): Maximum number of hops to trace
        timeout (int): Timeout in seconds for each probe
        
    Returns:
        str: Formatted traceroute results
    """
    logger.info(f"Starting traceroute to {host} with max hops {max_hops}, timeout {timeout}s")
    
    try:
        # Determine the traceroute command based on OS
        os_name = platform.system().lower()
        
        if os_name == "windows":
            # Windows uses 'tracert'
            command = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), host]
            
            # Windows doesn't accept -w 0, so if timeout is zero, use 1
            if timeout == 0:
                command[4] = "1"
        else:
            # Linux/macOS use 'traceroute'
            command = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
        
        # Execute the traceroute command
        result = subprocess.run(command, capture_output=True, text=True, timeout=max_hops * timeout + 10)
        
        # Format the output
        output = format_traceroute_output(result.stdout, host, os_name)
        logger.info(f"Traceroute to {host} completed successfully")
        return output
    
    except subprocess.TimeoutExpired:
        error_msg = f"Traceroute command timed out after {max_hops * timeout + 10} seconds"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Error executing traceroute: {str(e)}"
        logger.error(error_msg)
        return error_msg

def format_traceroute_output(output, host, os_name):
    """Format traceroute output to be more readable and add additional information"""
    lines = output.strip().split('\n')
    formatted_output = f"TRACEROUTE RESULTS: {host}\n{'-' * 60}\n"
    
    # Add the original output
    for line in lines:
        formatted_output += f"{line}\n"
    
    # Extract and add a summary
    hop_count = 0
    max_rtt = 0
    found_destination = False
    
    # Try to get destination IP
    destination_ip = None
    
    # Find the last line with an IP address
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    for line in reversed(lines):
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            destination_ip = ip_match.group(0)
            break
    
    # Windows tracert specific parsing
    if os_name == "windows":
        for line in lines:
            if re.search(r'^\s*\d+', line):
                hop_count += 1
            if "Request timed out" not in line and "* * *" not in line:
                # Extract RTTs from lines like "... 50 ms 49 ms 47 ms ..."
                rtts = re.findall(r'(\d+)\s*ms', line)
                if rtts:
                    max_rtt = max(max_rtt, max(int(rtt) for rtt in rtts))
            if host.lower() in line.lower() or (destination_ip and destination_ip in line):
                found_destination = True
    
    # Linux/macOS traceroute specific parsing
    else:
        for line in lines:
            if re.search(r'^\s*\d+\s+', line):
                hop_count += 1
            if "* * *" not in line:
                # Extract RTTs from lines like "... 50.123 ms 49.456 ms 47.789 ms"
                rtts = re.findall(r'([\d.]+)\s*ms', line)
                if rtts:
                    max_rtt = max(max_rtt, max(float(rtt) for rtt in rtts))
            if host.lower() in line.lower() or (destination_ip and destination_ip in line):
                found_destination = True
    
    # Add geographical information for the final hop if available
    geo_info = ""
    if destination_ip:
        try:
            hostname = socket.gethostbyaddr(destination_ip)[0]
            geo_info = f"\nDestination Hostname: {hostname}"
        except (socket.herror, socket.gaierror):
            pass
    
    # Add summary
    summary = f"\nSUMMARY:\n"
    summary += f"Total Hops: {hop_count}\n"
    summary += f"Maximum RTT: {max_rtt} ms\n"
    summary += f"Destination Reached: {'Yes' if found_destination else 'No'}\n"
    
    if destination_ip:
        summary += f"Destination IP: {destination_ip}{geo_info}\n"
    
    return formatted_output + summary