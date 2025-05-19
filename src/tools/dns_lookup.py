import dns.resolver
from dns.exception import DNSException
import socket
from ..utils.logger import get_logger

logger = get_logger("dns_tool")

def dns_lookup(domain, record_type="A", dns_server=None):
    """
    Perform a DNS lookup.
    
    Args:
        domain (str): The domain to look up
        record_type (str): DNS record type (A, AAAA, MX, NS, TXT, etc.)
        dns_server (str): Custom DNS server to use (optional)
        
    Returns:
        str: Formatted DNS lookup results
    """
    logger.info(f"Looking up {record_type} records for {domain}")
    
    if dns_server:
        logger.info(f"Using custom DNS server: {dns_server}")
    
    try:
        resolver = dns.resolver.Resolver()
        
        # Set custom DNS server if provided
        if dns_server:
            resolver.nameservers = [dns_server]
        
        # Perform the lookup
        answers = resolver.resolve(domain, record_type)
        
        # Format the results
        results = format_dns_results(domain, record_type, answers, dns_server)
        logger.info(f"DNS lookup successful with {len(answers)} results")
        return results
        
    except dns.resolver.NoAnswer:
        error_msg = f"No {record_type} records found for {domain}"
        logger.warning(error_msg)
        return error_msg
    except dns.resolver.NXDOMAIN:
        error_msg = f"Domain {domain} does not exist"
        logger.error(error_msg)
        return error_msg
    except DNSException as e:
        error_msg = f"DNS lookup error: {str(e)}"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Error performing DNS lookup: {str(e)}"
        logger.error(error_msg)
        return error_msg

def format_dns_results(domain, record_type, answers, dns_server=None):
    """Format DNS lookup results for display"""
    output = f"DNS LOOKUP RESULTS:\n{'-' * 60}\n"
    output += f"Domain: {domain}\n"
    output += f"Record Type: {record_type}\n"
    
    if dns_server:
        output += f"DNS Server: {dns_server}\n"
    else:
        output += "DNS Server: Default system resolver\n"
    
    output += f"\nFound {len(answers)} record(s):\n"
    output += f"{'-' * 60}\n"
    
    for i, answer in enumerate(answers, 1):
        output += f"Record {i}: {answer}\n"
        
        # Add additional info for certain record types
        if record_type == "A" or record_type == "AAAA":
            try:
                hostname = socket.gethostbyaddr(str(answer))[0]
                output += f"  Hostname: {hostname}\n"
            except (socket.herror, socket.gaierror):
                pass
        elif record_type == "MX":
            output += f"  Preference: {answer.preference}\n"
            output += f"  Exchange: {answer.exchange}\n"
        elif record_type == "SOA":
            output += f"  Primary NS: {answer.mname}\n"
            output += f"  Responsible: {answer.rname}\n"
            output += f"  Serial: {answer.serial}\n"
            output += f"  Refresh: {answer.refresh}\n"
            output += f"  Retry: {answer.retry}\n"
            output += f"  Expire: {answer.expire}\n"
            output += f"  Minimum TTL: {answer.minimum}\n"
    
    return output

def get_common_record_types():
    """Returns a list of common DNS record types"""
    return [
        "A",        # IPv4 address
        "AAAA",     # IPv6 address
        "MX",       # Mail exchange
        "NS",       # Name server
        "TXT",      # Text records
        "CNAME",    # Canonical name
        "SOA",      # Start of authority
        "PTR",      # Pointer (reverse DNS)
        "SRV",      # Service locator
        "CAA",      # Certification Authority Authorization
    ]