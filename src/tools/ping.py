import platform
import subprocess
import re
from ..utils.logger import get_logger

logger = get_logger("ping_tool")

def ping_host(host, count=4):
    """
    Ping a host and return the results.
    
    Args:
        host (str): The hostname or IP address to ping
        count (int): Number of ping packets to send
        
    Returns:
        str: Formatted ping results
    """
    logger.info(f"Pinging {host} with {count} packets")
    
    try:
        # Determine the ping command based on the operating system
        os_name = platform.system().lower()
        
        if os_name == "windows":
            command = ["ping", "-n", str(count), host]
        else:  # Linux, Darwin (macOS), etc.
            command = ["ping", "-c", str(count), host]
        
        # Execute the ping command
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            logger.info(f"Ping to {host} successful")
            return format_ping_output(result.stdout, os_name)
        else:
            error_msg = f"Ping failed with error: {result.stderr}"
            logger.error(error_msg)
            return error_msg
            
    except subprocess.TimeoutExpired:
        error_msg = "Ping command timed out after 15 seconds"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Error executing ping: {str(e)}"
        logger.error(error_msg)
        return error_msg

def format_ping_output(output, os_name):
    """Format ping output to be more readable"""
    lines = output.strip().split('\n')
    formatted_output = ""
    
    # Add header
    formatted_output += f"PING RESULTS:\n{'-' * 60}\n"
    
    # Add original output
    for line in lines:
        formatted_output += f"{line}\n"
    
    # Extract and add statistics summary
    summary = ""
    
    if os_name == "windows":
        # Extract packet statistics
        stats_match = re.search(r'Sent = (\d+), Received = (\d+), Lost = (\d+)', output)
        if stats_match:
            sent, received, lost = stats_match.groups()
            loss_percent = (int(lost) / int(sent)) * 100 if int(sent) > 0 else 0
            summary += f"\nSUMMARY:\n"
            summary += f"Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percent:.1f}% loss)\n"
        
        # Extract time statistics
        time_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
        if time_match:
            min_time, max_time, avg_time = time_match.groups()
            summary += f"Round-trip times: Minimum = {min_time}ms, Maximum = {max_time}ms, Average = {avg_time}ms\n"
    
    else:  # Linux, macOS
        # Extract packet statistics
        stats_match = re.search(r'(\d+) packets transmitted, (\d+) (packets |)received, (\d+\.?\d*)% packet loss', output)
        if stats_match:
            sent, received, _, loss_percent = stats_match.groups()
            summary += f"\nSUMMARY:\n"
            summary += f"Packets: Sent = {sent}, Received = {received}, Loss = {loss_percent}%\n"
        
        # Extract time statistics
        time_match = re.search(r'min/avg/max/(mdev|stddev) = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
        if time_match:
            _, min_time, avg_time, max_time, _ = time_match.groups()
            summary += f"Round-trip times: Minimum = {min_time}ms, Maximum = {max_time}ms, Average = {avg_time}ms\n"
    
    return formatted_output + summary
