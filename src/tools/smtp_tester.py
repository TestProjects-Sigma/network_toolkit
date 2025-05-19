import smtplib
import socket
import ssl
import threading
import time
import email.utils
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..utils.logger import get_logger

logger = get_logger("smtp_tool")

class SMTPTestResult:
    """Class to store SMTP test results"""
    def __init__(self):
        self.server = ""
        self.port = 0
        self.from_address = ""
        self.to_address = ""
        self.subject = ""
        self.body = ""
        self.use_tls = False
        self.use_ssl = False
        self.use_auth = False
        self.status = "Not started"
        self.success = False
        self.error = None
        self.detailed_log = []
        self.response_time = 0
        self.finished = False

def test_smtp_connection(server, port, timeout=5):
    """
    Test if an SMTP server is accessible on the specified port.
    
    Args:
        server (str): SMTP server hostname or IP
        port (int): SMTP server port
        timeout (int): Connection timeout in seconds
        
    Returns:
        tuple: (success, error_message)
    """
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            # Connection successful
            return True, None
    except socket.timeout:
        return False, f"Connection to {server}:{port} timed out after {timeout} seconds"
    except socket.gaierror:
        return False, f"Could not resolve hostname: {server}"
    except ConnectionRefusedError:
        return False, f"Connection to {server}:{port} was refused"
    except Exception as e:
        return False, f"Error connecting to {server}:{port}: {str(e)}"

def send_test_email(server, port, from_address, to_address, subject, body, 
                   use_tls=False, use_ssl=False, username=None, password=None,
                   progress_callback=None):
    """
    Send a test email through the specified SMTP server.
    
    Args:
        server (str): SMTP server hostname or IP
        port (int): SMTP server port
        from_address (str): Sender email address
        to_address (str): Recipient email address
        subject (str): Email subject
        body (str): Email body
        use_tls (bool): Whether to use STARTTLS
        use_ssl (bool): Whether to use SSL/TLS from the beginning
        username (str, optional): SMTP authentication username
        password (str, optional): SMTP authentication password
        progress_callback (function, optional): Callback for progress updates
        
    Returns:
        SMTPTestResult: Test results
    """
    result = SMTPTestResult()
    result.server = server
    result.port = port
    result.from_address = from_address
    result.to_address = to_address
    result.subject = subject
    result.body = body
    result.use_tls = use_tls
    result.use_ssl = use_ssl
    result.use_auth = bool(username and password)
    
    def log_step(message):
        """Add a step to the detailed log and update status"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        result.detailed_log.append(log_entry)
        result.status = message
        logger.info(message)
        if progress_callback:
            progress_callback(result)
    
    def run_test():
        """Run the SMTP test in a separate thread"""
        try:
            start_time = time.time()
            
            # Test basic connection first
            log_step(f"Testing connection to {server}:{port}...")
            connection_success, connection_error = test_smtp_connection(server, port)
            
            if not connection_success:
                result.error = connection_error
                log_step(f"Connection test failed: {connection_error}")
                return
            
            log_step("Connection successful")
            
            # Create the email message
            log_step("Creating email message...")
            message = MIMEMultipart()
            message["From"] = from_address
            message["To"] = to_address
            message["Subject"] = subject
            message["Date"] = email.utils.formatdate(localtime=True)
            message["Message-ID"] = email.utils.make_msgid(domain=from_address.split("@")[1] if "@" in from_address else "example.com")
            
            # Attach the body
            message.attach(MIMEText(body, "plain"))
            
            # Connect to the server
            try:
                if use_ssl:
                    log_step(f"Connecting to {server}:{port} using SSL...")
                    context = ssl.create_default_context()
                    smtp = smtplib.SMTP_SSL(server, port, context=context, timeout=10)
                else:
                    log_step(f"Connecting to {server}:{port}...")
                    smtp = smtplib.SMTP(server, port, timeout=10)
            except Exception as e:
                result.error = f"Failed to connect: {str(e)}"
                log_step(f"Connection failed: {str(e)}")
                return
            
            try:
                # Get the SMTP banner
                banner = smtp.ehlo_resp.decode() if hasattr(smtp, 'ehlo_resp') else "SMTP server connected"
                log_step(f"Connected to server: {banner}")
                
                # Start TLS if requested
                if use_tls and not use_ssl:
                    log_step("Starting TLS encryption...")
                    try:
                        context = ssl.create_default_context()
                        smtp.starttls(context=context)
                        smtp.ehlo()
                        log_step("TLS encryption established")
                    except Exception as e:
                        result.error = f"Failed to start TLS: {str(e)}"
                        log_step(f"TLS negotiation failed: {str(e)}")
                        smtp.close()
                        return
                
                # Authenticate if username and password provided
                if username and password:
                    log_step(f"Authenticating as {username}...")
                    try:
                        smtp.login(username, password)
                        log_step("Authentication successful")
                    except smtplib.SMTPAuthenticationError as e:
                        result.error = f"Authentication failed: {str(e)}"
                        log_step(f"Authentication failed: {str(e)}")
                        smtp.close()
                        return
                    except Exception as e:
                        result.error = f"Authentication error: {str(e)}"
                        log_step(f"Authentication error: {str(e)}")
                        smtp.close()
                        return
                
                # Send the email
                log_step(f"Sending email from {from_address} to {to_address}...")
                try:
                    smtp.sendmail(from_address, to_address, message.as_string())
                    log_step("Email sent successfully")
                    result.success = True
                except Exception as e:
                    result.error = f"Failed to send email: {str(e)}"
                    log_step(f"Send failed: {str(e)}")
                    return
                
                # Close the connection
                smtp.quit()
                log_step("SMTP connection closed")
                
                # Calculate response time
                end_time = time.time()
                result.response_time = end_time - start_time
                log_step(f"Test completed in {result.response_time:.2f} seconds")
                
            except Exception as e:
                result.error = f"SMTP test error: {str(e)}"
                log_step(f"Error during test: {str(e)}")
                try:
                    smtp.quit()
                except:
                    pass
                return
            
        except Exception as e:
            result.error = f"Test failed: {str(e)}"
            log_step(f"Test failed: {str(e)}")
        
        finally:
            result.finished = True
            if progress_callback:
                progress_callback(result)
    
    # Create and start the test thread
    test_thread = threading.Thread(target=run_test)
    test_thread.daemon = True
    test_thread.start()
    
    return result

def get_common_smtp_ports():
    """Return a list of common SMTP ports with descriptions"""
    return [
        (25, "SMTP (Standard, typically blocked by ISPs)"),
        (465, "SMTP over SSL (SMTPS, Implicit TLS)"),
        (587, "SMTP with STARTTLS (Submission Port, most common)"),
        (2525, "Alternative SMTP (used when 25/587 are blocked)")
    ]

def format_smtp_test_results(result):
    """Format SMTP test results for display"""
    if not result.finished:
        return "Test in progress...\n"
    
    output = f"SMTP TEST RESULTS: {result.server}:{result.port}\n{'-' * 60}\n"
    
    # Test details
    output += f"Server: {result.server}\n"
    output += f"Port: {result.port}\n"
    output += f"From: {result.from_address}\n"
    output += f"To: {result.to_address}\n"
    output += f"Subject: {result.subject}\n"
    output += f"TLS: {'Yes' if result.use_tls else 'No'}\n"
    output += f"SSL: {'Yes' if result.use_ssl else 'No'}\n"
    output += f"Authentication: {'Yes' if result.use_auth else 'No'}\n"
    
    # Test result
    output += f"\nRESULT: {'SUCCESS' if result.success else 'FAILED'}\n"
    if result.error:
        output += f"Error: {result.error}\n"
    
    if result.response_time > 0:
        output += f"Response Time: {result.response_time:.2f} seconds\n"
    
    # Detailed log
    output += f"\nDETAILED LOG:\n{'-' * 60}\n"
    for log_entry in result.detailed_log:
        output += f"{log_entry}\n"
    
    return output