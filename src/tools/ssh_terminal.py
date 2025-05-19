import paramiko
import threading
import time
import socket
from io import StringIO
from ..utils.logger import get_logger

logger = get_logger("ssh_terminal_tool")

class SSHConnection:
    """Class to handle SSH connections and terminal interaction"""
    def __init__(self):
        self.client = None
        self.channel = None
        self.transport = None
        self.hostname = ""
        self.username = ""
        self.connected = False
        self.output_callback = None
        self.stop_event = threading.Event()
    
    def connect(self, hostname, port, username, password=None, key_filename=None):
        """
        Connect to an SSH server.
        
        Args:
            hostname (str): The host to connect to
            port (int): The port to connect on
            username (str): The username to authenticate as
            password (str, optional): The password to authenticate with
            key_filename (str, optional): Path to private key file
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        self.hostname = hostname
        self.username = username
        
        try:
            logger.info(f"Connecting to {hostname}:{port} as {username}")
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': hostname,
                'port': port,
                'username': username,
                'timeout': 10
            }
            
            # Add authentication details
            if password:
                connect_kwargs['password'] = password
            if key_filename:
                connect_kwargs['key_filename'] = key_filename
            
            # Connect to the SSH server
            self.client.connect(**connect_kwargs)
            
            # Open a channel in the transport
            self.transport = self.client.get_transport()
            self.channel = self.transport.open_session()
            self.channel.get_pty()
            self.channel.invoke_shell()
            
            # Start reading output in a separate thread
            self.stop_event.clear()
            threading.Thread(target=self._read_output, daemon=True).start()
            
            self.connected = True
            logger.info(f"Successfully connected to {hostname}")
            return True
            
        except paramiko.AuthenticationException:
            error_msg = f"Authentication failed for {username}@{hostname}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg + "\n")
            return False
            
        except (socket.error, paramiko.SSHException) as e:
            error_msg = f"Error connecting to {hostname}: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg + "\n")
            return False
    
    def disconnect(self):
        """Disconnect from the SSH server."""
        if self.connected:
            logger.info(f"Disconnecting from {self.hostname}")
            self.stop_event.set()
            
            if self.channel:
                self.channel.close()
            
            if self.client:
                self.client.close()
            
            self.connected = False
            logger.info(f"Disconnected from {self.hostname}")
    
    def send_command(self, command):
        """
        Send a command to the SSH server.
        
        Args:
            command (str): The command to send
            
        Returns:
            bool: True if command was sent, False otherwise
        """
        if not self.connected or not self.channel:
            logger.error("Not connected to SSH server")
            return False
        
        try:
            # Add newline to execute the command
            if not command.endswith('\n'):
                command += '\n'
            
            logger.debug(f"Sending command: {command.strip()}")
            self.channel.send(command)
            return True
            
        except (socket.error, paramiko.SSHException) as e:
            error_msg = f"Error sending command: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                self.output_callback(error_msg + "\n")
            return False
    
    def _read_output(self):
        """Read output from the SSH channel and call the output callback."""
        if not self.channel:
            return
        
        buffer = StringIO()
        while not self.stop_event.is_set() and self.channel.recv_ready():
            try:
                data = self.channel.recv(1024).decode('utf-8', errors='replace')
                buffer.write(data)
                
                # Call output callback if set
                if self.output_callback:
                    self.output_callback(data)
                
            except (socket.error, paramiko.SSHException) as e:
                logger.error(f"Error reading from channel: {str(e)}")
                if self.output_callback:
                    self.output_callback(f"Error: {str(e)}\n")
                break
            
            # Sleep briefly to reduce CPU usage
            time.sleep(0.01)
        
        # Continue reading output
        if not self.stop_event.is_set():
            threading.Timer(0.1, self._read_output).start()