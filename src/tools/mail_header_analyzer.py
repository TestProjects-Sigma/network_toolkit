import re
import ipaddress
import email
import datetime
import socket
from email.utils import parsedate_to_datetime
from ..utils.logger import get_logger

logger = get_logger("mail_header_tool")

class HeaderAnalysisResult:
    """Class to store email header analysis results"""
    def __init__(self):
        self.raw_headers = ""
        self.parsed_headers = {}
        self.delivery_path = []
        self.auth_results = []
        self.spam_score = 0
        self.is_spam = False
        self.spf_result = None
        self.dkim_result = None
        self.dmarc_result = None
        self.sender_ip = None
        self.geo_info = None
        self.security_issues = []
        self.warnings = []
        self.delivery_time = None

def parse_email_headers(header_text):
    """
    Parse raw email headers into a structured format.
    
    Args:
        header_text (str): Raw email headers
        
    Returns:
        HeaderAnalysisResult: Analysis results
    """
    result = HeaderAnalysisResult()
    result.raw_headers = header_text
    
    logger.info("Starting email header analysis")
    
    try:
        # Parse headers with email.parser
        parser = email.parser.HeaderParser()
        headers = parser.parsestr(header_text)
        
        # Convert headers to dictionary for easier access
        for key in headers.keys():
            result.parsed_headers[key] = headers.get_all(key, [])
            
        # Analyze delivery path
        extract_delivery_path(result)
        
        # Analyze authentication results
        analyze_authentication(result)
        
        # Calculate delivery time
        calculate_delivery_time(result)
        
        # Check for security issues
        check_security_issues(result)
        
        # Estimate spam likelihood
        estimate_spam_likelihood(result)
        
        logger.info("Email header analysis completed successfully")
        
    except Exception as e:
        logger.error(f"Error analyzing email headers: {str(e)}")
        result.warnings.append(f"Error during analysis: {str(e)}")
    
    return result

def extract_delivery_path(result):
    """Extract the email delivery path from headers"""
    # We'll look at Received headers to reconstruct the delivery path
    if 'Received' in result.parsed_headers:
        received_headers = result.parsed_headers['Received']
        
        # Process in reverse order (last hop first)
        for header in reversed(received_headers):
            hop = {}
            
            # Extract server name/IP
            from_match = re.search(r'from\s+([^\s]+)(?:\s+\(([^\)]+)\))?', header)
            if from_match:
                hop['from_server'] = from_match.group(1)
                if from_match.group(2):
                    hop['from_info'] = from_match.group(2)
            
            # Extract recipient server
            by_match = re.search(r'by\s+([^\s;]+)', header)
            if by_match:
                hop['by_server'] = by_match.group(1)
            
            # Extract timestamp
            date_match = re.search(r';\s*(.+)$', header)
            if date_match:
                hop['timestamp'] = date_match.group(1).strip()
                try:
                    hop['datetime'] = parsedate_to_datetime(date_match.group(1).strip())
                except:
                    pass
            
            # Extract IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            if ip_matches:
                hop['ip_addresses'] = ip_matches
                
                # Store the first sender IP found (last Received header's IP)
                if not result.sender_ip and len(result.delivery_path) == 0:
                    result.sender_ip = ip_matches[0]
            
            # Add hop to delivery path
            if hop:
                result.delivery_path.append(hop)

def analyze_authentication(result):
    """Analyze authentication headers (SPF, DKIM, DMARC)"""
    # Check Authentication-Results header
    if 'Authentication-Results' in result.parsed_headers:
        for header in result.parsed_headers['Authentication-Results']:
            # Extract SPF result
            spf_match = re.search(r'spf=([^\s;]+)', header)
            if spf_match:
                result.spf_result = spf_match.group(1)
                result.auth_results.append(f"SPF: {result.spf_result}")
            
            # Extract DKIM result
            dkim_match = re.search(r'dkim=([^\s;]+)', header)
            if dkim_match:
                result.dkim_result = dkim_match.group(1)
                result.auth_results.append(f"DKIM: {result.dkim_result}")
            
            # Extract DMARC result
            dmarc_match = re.search(r'dmarc=([^\s;]+)', header)
            if dmarc_match:
                result.dmarc_result = dmarc_match.group(1)
                result.auth_results.append(f"DMARC: {result.dmarc_result}")
    
    # Also check for independent SPF/DKIM headers
    if 'Received-SPF' in result.parsed_headers and not result.spf_result:
        spf_header = result.parsed_headers['Received-SPF'][0]
        if 'pass' in spf_header.lower():
            result.spf_result = 'pass'
        elif 'fail' in spf_header.lower():
            result.spf_result = 'fail'
        elif 'neutral' in spf_header.lower():
            result.spf_result = 'neutral'
        
        if result.spf_result and 'SPF:' not in ' '.join(result.auth_results):
            result.auth_results.append(f"SPF: {result.spf_result}")
    
    if 'DKIM-Signature' in result.parsed_headers and not result.dkim_result:
        result.dkim_result = 'present'
        if 'DKIM:' not in ' '.join(result.auth_results):
            result.auth_results.append("DKIM: present (signature found)")

def calculate_delivery_time(result):
    """Calculate total email delivery time if possible"""
    if len(result.delivery_path) >= 2:
        try:
            # Try to find timestamps with datetime objects
            start_time = None
            end_time = None
            
            for hop in result.delivery_path:
                if 'datetime' in hop:
                    if not start_time:
                        start_time = hop['datetime']
                    end_time = hop['datetime']
            
            if start_time and end_time:
                # Calculate time difference
                time_diff = end_time - start_time
                result.delivery_time = time_diff
        except Exception as e:
            logger.error(f"Error calculating delivery time: {str(e)}")

def check_security_issues(result):
    """Check for security issues in headers"""
    # Check if sender IP is a known issue
    if result.sender_ip:
        # Private IP range check
        try:
            ip = ipaddress.ip_address(result.sender_ip)
            if ip.is_private:
                result.security_issues.append(f"Sender IP {result.sender_ip} is a private IP address")
        except:
            pass
    
    # Check SPF/DKIM/DMARC failures
    if result.spf_result and result.spf_result.lower() == 'fail':
        result.security_issues.append("SPF verification failed")
    
    if result.dkim_result and result.dkim_result.lower() == 'fail':
        result.security_issues.append("DKIM signature verification failed")
    
    if result.dmarc_result and result.dmarc_result.lower() == 'fail':
        result.security_issues.append("DMARC verification failed")
    
    # Check for missing security
    if not result.spf_result:
        result.warnings.append("No SPF verification found")
    
    if not result.dkim_result:
        result.warnings.append("No DKIM signature found")
    
    if not result.dmarc_result:
        result.warnings.append("No DMARC policy found")
    
    # Check for unusual hops or delays
    if len(result.delivery_path) > 10:
        result.warnings.append(f"Unusually many hops ({len(result.delivery_path)})")

def estimate_spam_likelihood(result):
    """Estimate likelihood of the email being spam"""
    score = 0
    
    # Authentication failures increase spam score
    if result.spf_result and result.spf_result.lower() == 'fail':
        score += 3
    
    if result.dkim_result and result.dkim_result.lower() == 'fail':
        score += 3
    
    if result.dmarc_result and result.dmarc_result.lower() == 'fail':
        score += 3
    
    # Missing authentication slightly increases spam score
    if not result.spf_result:
        score += 1
    
    if not result.dkim_result:
        score += 1
    
    if not result.dmarc_result:
        score += 1
    
    # Check for spam-related headers
    spam_headers = ['X-Spam-Flag', 'X-Spam-Status', 'X-Spam-Level']
    for header in spam_headers:
        if header in result.parsed_headers:
            for value in result.parsed_headers[header]:
                if 'yes' in value.lower() or 'true' in value.lower():
                    score += 5
                    break
    
    # Check for excessive hops
    if len(result.delivery_path) > 10:
        score += 2
    
    # Set final score and spam determination
    result.spam_score = score
    result.is_spam = score >= 5

def format_header_analysis(result):
    """Format header analysis results for display"""
    output = f"EMAIL HEADER ANALYSIS\n{'-' * 60}\n"
    
    # Basic information
    if 'From' in result.parsed_headers:
        output += f"From: {result.parsed_headers['From'][0]}\n"
    
    if 'To' in result.parsed_headers:
        output += f"To: {result.parsed_headers['To'][0]}\n"
    
    if 'Subject' in result.parsed_headers:
        output += f"Subject: {result.parsed_headers['Subject'][0]}\n"
    
    if 'Date' in result.parsed_headers:
        output += f"Date: {result.parsed_headers['Date'][0]}\n"
    
    # Authentication results
    output += f"\nAUTHENTICATION RESULTS:\n{'-' * 60}\n"
    if result.auth_results:
        for auth in result.auth_results:
            output += f"• {auth}\n"
    else:
        output += "No authentication results found\n"
    
    # Spam assessment
    output += f"\nSPAM ASSESSMENT:\n{'-' * 60}\n"
    output += f"Spam Score: {result.spam_score}/10\n"
    output += f"Likelihood: {'High' if result.is_spam else 'Low'}\n"
    
    # Security issues
    output += f"\nSECURITY ISSUES:\n{'-' * 60}\n"
    if result.security_issues:
        for issue in result.security_issues:
            output += f"⚠️ {issue}\n"
    else:
        output += "No security issues found\n"
    
    # Warnings
    if result.warnings:
        output += f"\nWARNINGS:\n{'-' * 60}\n"
        for warning in result.warnings:
            output += f"⚠️ {warning}\n"
    
    # Delivery path
    output += f"\nDELIVERY PATH:\n{'-' * 60}\n"
    if result.delivery_path:
        for i, hop in enumerate(result.delivery_path, 1):
            output += f"Hop {i}:\n"
            
            if 'from_server' in hop:
                output += f"  From: {hop['from_server']}"
                if 'from_info' in hop:
                    output += f" ({hop['from_info']})"
                output += "\n"
            
            if 'by_server' in hop:
                output += f"  To: {hop['by_server']}\n"
            
            if 'timestamp' in hop:
                output += f"  Time: {hop['timestamp']}\n"
            
            if 'ip_addresses' in hop:
                output += f"  IPs: {', '.join(hop['ip_addresses'])}\n"
            
            output += "\n"
        
        # Add delivery time if calculated
        if result.delivery_time:
            seconds = result.delivery_time.total_seconds()
            if seconds < 60:
                time_str = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds/60:.1f} minutes"
            else:
                time_str = f"{seconds/3600:.1f} hours"
            
            output += f"Total delivery time: {time_str}\n"
    else:
        output += "No delivery path information found\n"
    
    # Headers summary
    output += f"\nHEADERS SUMMARY:\n{'-' * 60}\n"
    output += f"Total Headers: {len(result.parsed_headers)}\n"
    output += "Important headers found:\n"
    important_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                        'Return-Path', 'Sender', 'Reply-To',
                        'Authentication-Results', 'DKIM-Signature',
                        'Received-SPF', 'X-Spam-Status']
    
    for header in important_headers:
        if header in result.parsed_headers:
            output += f"• {header}\n"
    
    return output

def get_example_header():
    """Return an example email header for demonstration purposes"""
    return """Received: from mail-ej1-f48.google.com (mail-ej1-f48.google.com [209.85.218.48])
    by mx.example.com (Postfix) with ESMTPS id 1234ABCD
    for <recipient@example.com>; Wed, 29 Apr 2023 14:18:28 +0000 (UTC)
Received: by mail-ej1-f48.google.com with SMTP id ab1cdef2.28
    for <recipient@example.com>; Wed, 29 Apr 2023 07:18:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=gmail.com; s=20210112; t=1682777908;
    h=from:to:subject:message-id:date:mime-version:from:to:cc:subject:date;
    bh=12345abcde67890ABCDEF1234567890abcdef1234567890ABCDEF=;
    b=ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef1234567890ABCDEF
Authentication-Results: mx.example.com;
    dkim=pass header.i=@gmail.com header.s=20210112;
    spf=pass (example.com: domain of sender@gmail.com designates 209.85.218.48 as permitted sender) smtp.mailfrom=sender@gmail.com;
    dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received-SPF: pass (example.com: domain of sender@gmail.com designates 209.85.218.48 as permitted sender) client-ip=209.85.218.48; envelope-from=sender@gmail.com; helo=mail-ej1-f48.google.com;
From: "Sender Name" <sender@gmail.com>
To: recipient@example.com
Subject: Test Email Subject
Message-ID: <ABCDEF1234567890@mail.gmail.com>
Date: Wed, 29 Apr 2023 07:18:28 -0700
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="000000000000abcdef1234567890"
X-Spam-Status: No, score=0.0
X-Original-Authentication-Results: mx.google.com;
    dkim=pass header.i=@gmail.com header.s=20210112;
    spf=pass (google.com: domain of sender@gmail.com designates 209.85.218.48 as permitted sender) smtp.mailfrom=sender@gmail.com;
    dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
"""