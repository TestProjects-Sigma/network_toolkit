import whois
import datetime
from ..utils.logger import get_logger

logger = get_logger("whois_tool")

def whois_lookup(domain):
    """
    Perform a WHOIS lookup on a domain.
    
    Args:
        domain (str): Domain name to look up
        
    Returns:
        str: Formatted WHOIS lookup results
    """
    logger.info(f"Starting WHOIS lookup for domain: {domain}")
    
    try:
        # Perform the WHOIS lookup
        domain_info = whois.whois(domain)
        
        # Format the results
        results = format_whois_results(domain, domain_info)
        logger.info(f"WHOIS lookup for {domain} completed successfully")
        return results
        
    except Exception as e:
        error_msg = f"Error performing WHOIS lookup: {str(e)}"
        logger.error(error_msg)
        return error_msg

def format_whois_results(domain, domain_info):
    """Format WHOIS lookup results for display"""
    output = f"WHOIS LOOKUP RESULTS: {domain}\n{'-' * 60}\n"
    
    # Check if we got valid data
    if not domain_info or not domain_info.domain_name:
        return f"{output}No WHOIS data found for {domain}."
    
    # Basic domain information
    output += "DOMAIN INFORMATION:\n"
    
    # Domain name (might be a list or a string)
    if isinstance(domain_info.domain_name, list):
        output += f"Domain Name: {', '.join(domain_info.domain_name)}\n"
    else:
        output += f"Domain Name: {domain_info.domain_name}\n"
    
    # Registrar
    if domain_info.registrar:
        output += f"Registrar: {domain_info.registrar}\n"
    
    # WHOIS Server
    if domain_info.whois_server:
        output += f"WHOIS Server: {domain_info.whois_server}\n"
    
    # Creation date
    if domain_info.creation_date:
        dates = format_date_list(domain_info.creation_date)
        output += f"Creation Date: {dates}\n"
    
    # Expiration date
    if domain_info.expiration_date:
        dates = format_date_list(domain_info.expiration_date)
        output += f"Expiration Date: {dates}\n"
    
    # Last updated
    if domain_info.updated_date:
        dates = format_date_list(domain_info.updated_date)
        output += f"Last Updated: {dates}\n"
    
    # Status
    if domain_info.status:
        if isinstance(domain_info.status, list):
            output += f"Status: {', '.join(domain_info.status)}\n"
        else:
            output += f"Status: {domain_info.status}\n"
    
    # Name servers
    if domain_info.name_servers:
        if isinstance(domain_info.name_servers, list):
            output += f"Name Servers: {', '.join(domain_info.name_servers)}\n"
        else:
            output += f"Name Servers: {domain_info.name_servers}\n"
    
    # Registrant information
    output += "\nREGISTRANT INFORMATION:\n"
    
    # Try to get registrant information if available
    fields = {
        'org': 'Organization',
        'registrant_org': 'Organization',
        'registrant_name': 'Name',
        'registrant_country': 'Country',
        'registrant_state': 'State/Province',
        'registrant_city': 'City',
        'registrant_email': 'Email'
    }
    
    for field, label in fields.items():
        if hasattr(domain_info, field) and getattr(domain_info, field):
            output += f"{label}: {getattr(domain_info, field)}\n"
    
    # Add domain age calculation
    if domain_info.creation_date:
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if isinstance(creation_date, datetime.datetime):
            age = calculate_domain_age(creation_date)
            output += f"\nDOMAIN AGE: {age}\n"
    
    # Add the raw WHOIS data
    output += f"\nRAW WHOIS DATA:\n{'-' * 60}\n"
    output += str(domain_info)
    
    return output

def format_date_list(date_value):
    """Format a date value that could be a list or a single date"""
    if isinstance(date_value, list):
        # Format each date in the list
        formatted_dates = []
        for date in date_value:
            if isinstance(date, datetime.datetime):
                formatted_dates.append(date.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                formatted_dates.append(str(date))
        return ', '.join(formatted_dates)
    elif isinstance(date_value, datetime.datetime):
        # Format a single datetime
        return date_value.strftime('%Y-%m-%d %H:%M:%S')
    else:
        # Return as string for any other type
        return str(date_value)

def calculate_domain_age(creation_date):
    """Calculate and format the age of a domain from its creation date"""
    now = datetime.datetime.now()
    if creation_date.tzinfo:
        now = datetime.datetime.now(creation_date.tzinfo)
    
    age = now - creation_date
    
    years = age.days // 365
    months = (age.days % 365) // 30
    days = (age.days % 365) % 30
    
    age_parts = []
    if years > 0:
        age_parts.append(f"{years} year{'s' if years != 1 else ''}")
    if months > 0:
        age_parts.append(f"{months} month{'s' if months != 1 else ''}")
    if days > 0 or not age_parts:
        age_parts.append(f"{days} day{'s' if days != 1 else ''}")
    
    return ', '.join(age_parts)