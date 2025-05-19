import customtkinter as ctk
import threading
from ..tools.ping import ping_host
from ..tools.dns_lookup import dns_lookup, get_common_record_types
from ..utils.logger import setup_logger
from ..tools.traceroute import traceroute
from ..tools.speedtest import run_speed_test, format_speed_test_results
from ..tools.whois_lookup import whois_lookup
from ..tools.port_scanner import scan_ports, get_common_ports, format_scan_results
from ..tools.ssh_terminal import SSHConnection
from ..tools.smtp_tester import send_test_email, get_common_smtp_ports, format_smtp_test_results
from ..tools.mail_header_analyzer import parse_email_headers, format_header_analysis, get_example_header
from ..tools.packet_analyzer import (
    PacketCaptureSession, get_available_interfaces, 
    format_packet, format_capture_stats, SCAPY_AVAILABLE
)

class NetworkToolkitApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Set up logging
        self.logger = setup_logger("network_toolkit", "logs/app.log")
        self.logger.info("Application started")
        
        # Configure window
        self.title("Network Toolkit")
        self.geometry("950x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configure grid layout
        self.grid_columnconfigure(0, weight=0)  # Fixed width for sidebar
        self.grid_columnconfigure(1, weight=1)  # Content area expands
        self.grid_rowconfigure(0, weight=1)
        
        # Create sidebar frame with fixed width
        self.sidebar_frame = ctk.CTkFrame(self, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        # Fix the sidebar width and prevent resizing
        self.sidebar_frame.configure(width=250)
        self.sidebar_frame.grid_propagate(False)
        
        # App title in sidebar
        self.app_title = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Network Toolkit", 
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="center"
        )
        self.app_title.grid(row=0, column=0, padx=20, pady=(20, 20), sticky="ew")
        
        # Fixed button width - ensure it fits within the sidebar
        button_width = 210
        
        # Create button frame to contain all buttons with fixed width
        self.button_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.button_container.grid(row=1, column=0, padx=0, pady=0, sticky="nsew")
        self.button_container.grid_columnconfigure(0, weight=1)
        
        # Button configurations with uniform creation
        button_configs = [
            {"name": "ping_button", "text": "Ping", "command": self.show_ping_tool},
            {"name": "dns_button", "text": "DNS Lookup", "command": self.show_dns_tool},
            {"name": "tracert_button", "text": "Traceroute", "command": self.show_traceroute_tool},
            {"name": "speedtest_button", "text": "Speed Test", "command": self.show_speedtest_tool},
            {"name": "whois_button", "text": "WHOIS", "command": self.show_whois_tool},
            {"name": "port_scan_button", "text": "Port Scanner", "command": self.show_port_scanner_tool},
            {"name": "ssh_terminal_button", "text": "SSH Terminal", "command": self.show_ssh_terminal_tool},
            {"name": "smtp_tester_button", "text": "SMTP Tester", "command": self.show_smtp_tester_tool},
            {"name": "mail_header_button", "text": "Header Analyzer", "command": self.show_mail_header_tool},
            {
                "name": "packet_analyzer_button", 
                "text": "Packet Analyzer", 
                "command": self.show_packet_analyzer_tool, 
                "state": "normal" if SCAPY_AVAILABLE else "disabled"
            }
        ]
        
        # Create buttons with absolute uniformity
        for i, config in enumerate(button_configs):
            # Create a subframe for each button to maintain consistent width
            button_frame = ctk.CTkFrame(self.button_container, fg_color="transparent")
            button_frame.grid(row=i, column=0, padx=20, pady=5, sticky="ew")
            button_frame.grid_columnconfigure(0, weight=1)
            
            # Create the button with fixed width
            button = ctk.CTkButton(
                button_frame,
                text=config["text"],
                command=config["command"],
                state=config.get("state", "normal"),
                width=button_width,
                height=32,
                corner_radius=8,
            )
            button.grid(row=0, column=0, sticky="ew")
            
            # Store the button as an instance attribute
            setattr(self, config["name"], button)
        
        # Main content frame
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(1, weight=1)
        
        # Initially show ping tool
        self.show_ping_tool()
    
    def show_ping_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Ping Tool", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create form frame with more space
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Host input
        host_label = ctk.CTkLabel(form_frame, text="Host:")
        host_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.host_entry = ctk.CTkEntry(form_frame, width=300)
        self.host_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.host_entry.insert(0, "google.com")
        
        # Count input
        count_label = ctk.CTkLabel(form_frame, text="Count:")
        count_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.count_entry = ctk.CTkEntry(form_frame, width=100)
        self.count_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.count_entry.insert(0, "4")
        
        # Ping button - ensure it's fully visible
        self.ping_execute_button = ctk.CTkButton(form_frame, text="Execute Ping", command=self.execute_ping, width=120)
        self.ping_execute_button.grid(row=2, column=1, padx=10, pady=(10, 20), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Output:")
        output_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)
    
    def execute_ping(self):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", "Pinging, please wait...\n")
        self.ping_execute_button.configure(state="disabled", text="Pinging...")
        
        host = self.host_entry.get()
        try:
            count = int(self.count_entry.get())
        except ValueError:
            count = 4
            self.count_entry.delete(0, "end")
            self.count_entry.insert(0, "4")
        
        # Log the action
        self.logger.info(f"Executing ping to {host} with count {count}")
        
        # Run ping in a separate thread to avoid freezing the GUI
        threading.Thread(target=self._run_ping, args=(host, count), daemon=True).start()
    
    def _run_ping(self, host, count):
        results = ping_host(host, count)
        
        # Update UI in the main thread
        self.after(0, lambda: self._update_ping_results(results))
    
    def _update_ping_results(self, results):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", results)
        self.ping_execute_button.configure(state="normal", text="Execute Ping")
        
        # Log completion
        self.logger.info("Ping execution completed")
    
    # Add the DNS lookup UI method
    def show_dns_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="DNS Lookup Tool", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create form frame with more space
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Domain input
        domain_label = ctk.CTkLabel(form_frame, text="Domain:")
        domain_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.domain_entry = ctk.CTkEntry(form_frame, width=300)
        self.domain_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.domain_entry.insert(0, "example.com")
        
        # Record type selection
        record_type_label = ctk.CTkLabel(form_frame, text="Record Type:")
        record_type_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.record_type_combobox = ctk.CTkComboBox(form_frame, values=get_common_record_types())
        self.record_type_combobox.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        # Custom DNS server (optional)
        dns_server_label = ctk.CTkLabel(form_frame, text="DNS Server:")
        dns_server_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.dns_server_entry = ctk.CTkEntry(form_frame, width=300)
        self.dns_server_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        self.dns_server_entry.insert(0, "8.8.8.8")
        
        # Info label
        info_label = ctk.CTkLabel(form_frame, text="(Leave empty to use system DNS)")
        info_label.grid(row=3, column=1, padx=10, pady=(0, 10), sticky="w")
        
        # Lookup button - ensure it's fully visible
        self.dns_execute_button = ctk.CTkButton(form_frame, text="Lookup", command=self.execute_dns_lookup, width=120)
        self.dns_execute_button.grid(row=4, column=1, padx=10, pady=(10, 20), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Output:")
        output_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)
    
    def execute_dns_lookup(self):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", "Performing DNS lookup, please wait...\n")
        self.dns_execute_button.configure(state="disabled", text="Looking up...")
        
        domain = self.domain_entry.get()
        record_type = self.record_type_combobox.get()
        dns_server = self.dns_server_entry.get() if self.dns_server_entry.get() else None
        
        # Log the action
        self.logger.info(f"Executing DNS lookup for {domain} with record type {record_type}")
        
        # Run lookup in a separate thread to avoid freezing the GUI
        threading.Thread(target=self._run_dns_lookup, args=(domain, record_type, dns_server), daemon=True).start()
    
    def _run_dns_lookup(self, domain, record_type, dns_server):
        results = dns_lookup(domain, record_type, dns_server)
        
        # Update UI in the main thread
        self.after(0, lambda: self._update_dns_results(results))
    
    def _update_dns_results(self, results):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", results)
        self.dns_execute_button.configure(state="normal", text="Lookup")
        
        # Log completion
        self.logger.info("DNS lookup completed")

    def show_traceroute_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Traceroute Tool", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create form frame with more space
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Host input
        host_label = ctk.CTkLabel(form_frame, text="Host:")
        host_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.tracert_host_entry = ctk.CTkEntry(form_frame, width=300)
        self.tracert_host_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.tracert_host_entry.insert(0, "google.com")
        
        # Max hops input
        max_hops_label = ctk.CTkLabel(form_frame, text="Max Hops:")
        max_hops_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.max_hops_entry = ctk.CTkEntry(form_frame, width=100)
        self.max_hops_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.max_hops_entry.insert(0, "30")
        
        # Timeout input
        timeout_label = ctk.CTkLabel(form_frame, text="Timeout (s):")
        timeout_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.timeout_entry = ctk.CTkEntry(form_frame, width=100)
        self.timeout_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        self.timeout_entry.insert(0, "2")
        
        # Traceroute button - ensure it's fully visible
        self.tracert_execute_button = ctk.CTkButton(form_frame, text="Execute Traceroute", 
                                                  command=self.execute_traceroute, width=150)
        self.tracert_execute_button.grid(row=3, column=1, padx=10, pady=(10, 20), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Output:")
        output_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)

    def execute_traceroute(self):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", "Executing traceroute, please wait...\n")
        self.tracert_execute_button.configure(state="disabled", text="Tracing route...")
        
        host = self.tracert_host_entry.get()
        
        try:
            max_hops = int(self.max_hops_entry.get())
            if max_hops < 1:
                max_hops = 30
                self.max_hops_entry.delete(0, "end")
                self.max_hops_entry.insert(0, "30")
        except ValueError:
            max_hops = 30
            self.max_hops_entry.delete(0, "end")
            self.max_hops_entry.insert(0, "30")
            
        try:
            timeout = int(self.timeout_entry.get())
            if timeout < 1:
                timeout = 2
                self.timeout_entry.delete(0, "end")
                self.timeout_entry.insert(0, "2")
        except ValueError:
            timeout = 2
            self.timeout_entry.delete(0, "end")
            self.timeout_entry.insert(0, "2")
        
        # Log the action
        self.logger.info(f"Executing traceroute to {host} with max hops {max_hops}, timeout {timeout}s")
        
        # Run traceroute in a separate thread to avoid freezing the GUI
        threading.Thread(target=self._run_traceroute, 
                         args=(host, max_hops, timeout), 
                         daemon=True).start()

    def _run_traceroute(self, host, max_hops, timeout):
        results = traceroute(host, max_hops, timeout)
        
        # Update UI in the main thread
        self.after(0, lambda: self._update_traceroute_results(results))

    def _update_traceroute_results(self, results):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", results)
        self.tracert_execute_button.configure(state="normal", text="Execute Traceroute")
        
        # Log completion
        self.logger.info("Traceroute execution completed")

    def show_speedtest_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Network Speed Test", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create info frame
        info_frame = ctk.CTkFrame(self.content_frame)
        info_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        info_frame.grid_columnconfigure(0, weight=1)
        
        # Info text
        info_text = ("This tool measures your network connection performance including:\n"
                    "• Download speed\n"
                    "• Upload speed\n"
                    "• Ping (latency)\n\n"
                    "The test may take up to 1 minute to complete. Your connection will be "
                    "actively used during the test.")
        
        info_label = ctk.CTkLabel(info_frame, text=info_text, justify="left")
        info_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")
        
        # Create button frame
        button_frame = ctk.CTkFrame(self.content_frame)
        button_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="new")
        button_frame.grid_columnconfigure(1, weight=1)
        
        # Speed test button - ensure it's fully visible
        self.speedtest_execute_button = ctk.CTkButton(button_frame, text="Start Speed Test", 
                                                   command=self.execute_speedtest, width=150)
        self.speedtest_execute_button.grid(row=0, column=0, padx=(20, 10), pady=20, sticky="w")
        
        # Progress bar and status
        self.progress_frame = ctk.CTkFrame(button_frame)
        self.progress_frame.grid(row=0, column=1, padx=(10, 20), pady=20, sticky="ew")
        self.progress_frame.grid_columnconfigure(0, weight=1)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, width=300)
        self.progress_bar.grid(row=0, column=0, padx=10, pady=(5, 0), sticky="ew")
        self.progress_bar.set(0)
        
        self.status_label = ctk.CTkLabel(self.progress_frame, text="Ready to start test")
        self.status_label.grid(row=1, column=0, padx=10, pady=(5, 5), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Results:")
        output_label.grid(row=3, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(4, weight=1)
        
        # Initial message
        self.output_textbox.insert("1.0", "Click 'Start Speed Test' to begin measuring your network performance.")

    def execute_speedtest(self):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", "Starting speed test, please wait...\n")
        self.speedtest_execute_button.configure(state="disabled", text="Testing...")
        self.progress_bar.set(0)
        self.status_label.configure(text="Initializing...")
        
        # Log the action
        self.logger.info("Starting network speed test")
        
        # Run speed test with progress updates
        self.speed_test_result = run_speed_test(self.update_speedtest_progress)

    def update_speedtest_progress(self, result):
        """Update the UI with current speed test progress"""
        # Update progress bar
        self.progress_bar.set(result.progress / 100)
        
        # Update status
        self.status_label.configure(text=result.status)
        
        # If finished, update results
        if result.finished:
            if result.error:
                self.output_textbox.delete("1.0", "end")
                self.output_textbox.insert("end", f"Error during speed test: {result.error}")
                self.logger.error(f"Speed test failed: {result.error}")
            else:
                self.output_textbox.delete("1.0", "end")
                formatted_results = format_speed_test_results(result)
                self.output_textbox.insert("end", formatted_results)
                self.logger.info("Speed test completed successfully")
            
            # Re-enable the button
            self.speedtest_execute_button.configure(state="normal", text="Start Speed Test")

    def show_whois_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="WHOIS Lookup Tool", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create form frame with more space
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Info text
        info_text = ("WHOIS provides information about domain registration, including:\n"
                   "• Domain owner (if available)\n"
                   "• Registration and expiration dates\n"
                   "• Nameservers\n"
                   "• Registrar information")
        
        info_label = ctk.CTkLabel(form_frame, text=info_text, justify="left")
        info_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="w")
        
        # Domain input
        domain_label = ctk.CTkLabel(form_frame, text="Domain:")
        domain_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.whois_domain_entry = ctk.CTkEntry(form_frame, width=300)
        self.whois_domain_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.whois_domain_entry.insert(0, "example.com")
        
        # Execute button
        self.whois_execute_button = ctk.CTkButton(form_frame, text="Lookup", 
                                              command=self.execute_whois, width=120)
        self.whois_execute_button.grid(row=2, column=1, padx=10, pady=(10, 20), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Results:")
        output_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)
        
        # Initial message
        self.output_textbox.insert("1.0", "Enter a domain name and click 'Lookup' to retrieve WHOIS information.")

    def execute_whois(self):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", "Performing WHOIS lookup, please wait...\n")
        self.whois_execute_button.configure(state="disabled", text="Looking up...")
        
        domain = self.whois_domain_entry.get()
        
        # Log the action
        self.logger.info(f"Executing WHOIS lookup for {domain}")
        
        # Run whois lookup in a separate thread to avoid freezing the GUI
        threading.Thread(target=self._run_whois, args=(domain,), daemon=True).start()

    def _run_whois(self, domain):
        results = whois_lookup(domain)
        
        # Update UI in the main thread
        self.after(0, lambda: self._update_whois_results(results))

    def _update_whois_results(self, results):
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", results)
        self.whois_execute_button.configure(state="normal", text="Lookup")
      
        # Log completion
        self.logger.info("WHOIS lookup completed")

    def show_port_scanner_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Port Scanner", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create main frame
        main_frame = ctk.CTkFrame(self.content_frame)
        main_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Warning message
        warning_text = ("WARNING: Port scanning may be against the Terms of Service of your network or ISP.\n"
                       "Only scan hosts you have permission to scan.")
        
        warning_label = ctk.CTkLabel(main_frame, text=warning_text, 
                                   text_color=("red", "red"), wraplength=800)
        warning_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(10, 10), sticky="w")
        
        # Create the settings section
        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.grid(row=1, column=0, padx=20, pady=(10, 10), sticky="new")
        settings_frame.grid_columnconfigure(1, weight=1)
        
        # Host input
        host_label = ctk.CTkLabel(settings_frame, text="Host:")
        host_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.port_scan_host_entry = ctk.CTkEntry(settings_frame, width=300)
        self.port_scan_host_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.port_scan_host_entry.insert(0, "localhost")
        
        # Port selection section
        ports_label = ctk.CTkLabel(settings_frame, text="Ports to scan:", font=ctk.CTkFont(weight="bold"))
        ports_label.grid(row=1, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="w")
        
        # Common ports checkboxes - Arranged in a more compact grid
        common_ports_frame = ctk.CTkFrame(settings_frame)
        common_ports_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        common_ports_frame.grid_columnconfigure((0,1,2,3,4), weight=1)  # 5 columns
        
        # Get common ports list
        common_ports = [
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
            (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
            (3306, "MySQL"), (3389, "RDP"), (8080, "HTTP-Proxy")
        ]
        
        # Create a dictionary to store the checkbox variables
        self.port_checkboxes = {}
        
        # Create checkboxes for common ports, 5 per row
        for i, (port, service) in enumerate(common_ports):
            row = i // 5
            col = i % 5
            
            # Create a variable for the checkbox
            var = ctk.BooleanVar(value=False)
            self.port_checkboxes[port] = var
            
            # Create the checkbox
            checkbox = ctk.CTkCheckBox(common_ports_frame, text=f"{port} ({service})",
                                     variable=var, onvalue=True, offvalue=False)
            checkbox.grid(row=row, column=col, padx=10, pady=5, sticky="w")
        
        # Custom port range input
        custom_ports_label = ctk.CTkLabel(settings_frame, text="Custom ports:", font=ctk.CTkFont(weight="bold"))
        custom_ports_label.grid(row=3, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="w")
        
        custom_ports_help = ctk.CTkLabel(settings_frame, 
                                       text="Enter port numbers separated by commas (e.g., 8000,8080,9000)",
                                       font=ctk.CTkFont(size=12))
        custom_ports_help.grid(row=4, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="w")
        
        self.custom_ports_entry = ctk.CTkEntry(settings_frame, width=300)
        self.custom_ports_entry.grid(row=5, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        
        # Important: Action buttons section - ENSURE VISIBILITY
        action_frame = ctk.CTkFrame(main_frame, fg_color=("#E3E3E3", "#333333"))  # Highlighted background
        action_frame.grid(row=2, column=0, padx=20, pady=20, sticky="ew")
        action_frame.grid_columnconfigure(1, weight=1)
        
        # Scan button - Make it prominent
        self.port_scan_button = ctk.CTkButton(
            action_frame, 
            text="Start Scan", 
            command=self.execute_port_scan, 
            width=150,
            height=40,  # Taller button
            font=ctk.CTkFont(size=14, weight="bold")  # Larger font
        )
        self.port_scan_button.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        # Status label
        self.port_scan_status_label = ctk.CTkLabel(action_frame, text="Ready to scan")
        self.port_scan_status_label.grid(row=0, column=1, padx=20, pady=15, sticky="w")
        
        # IMPORTANT: Progress Bar - Separate location
        self.port_scan_progress_bar = ctk.CTkProgressBar(action_frame, width=300)
        self.port_scan_progress_bar.grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 15), sticky="ew")
        self.port_scan_progress_bar.set(0)
        
        # Results section - BELOW the action buttons
        results_frame = ctk.CTkFrame(main_frame)
        results_frame.grid(row=3, column=0, padx=20, pady=(20, 20), sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)
        
        # Results label
        results_label = ctk.CTkLabel(results_frame, text="Results:", font=ctk.CTkFont(weight="bold"))
        results_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        # Output text area
        self.output_textbox = ctk.CTkTextbox(results_frame, height=200)
        self.output_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        # Make the results frame expandable
        main_frame.grid_rowconfigure(3, weight=1)
        
        # Initial message
        self.output_textbox.insert("1.0", "Select ports to scan and click 'Start Scan'.\n\n"
                                 "WARNING: Only scan systems you have permission to scan.")

    def execute_port_scan(self):
        # Get the host
        host = self.port_scan_host_entry.get()
        if not host:
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: Please enter a host to scan")
            return
        
        # Get selected ports
        ports_to_scan = []
        
        # Add checked common ports
        for port, var in self.port_checkboxes.items():
            if var.get():
                ports_to_scan.append(port)
        
        # Add custom ports
        custom_ports = self.custom_ports_entry.get().strip()
        if custom_ports:
            try:
                for port_str in custom_ports.split(','):
                    port = int(port_str.strip())
                    if 1 <= port <= 65535 and port not in ports_to_scan:
                        ports_to_scan.append(port)
            except ValueError:
                self.output_textbox.delete("1.0", "end")
                self.output_textbox.insert("end", "Error: Invalid port number in custom ports field")
                return
        
        # Check if any ports are selected
        if not ports_to_scan:
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: Please select at least one port to scan")
            return
        
        # Start the scan
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", f"Starting port scan of {host}, please wait...\n")
        self.port_scan_button.configure(state="disabled", text="Scanning...")
        self.port_scan_progress_bar.set(0)
        self.port_scan_status_label.configure(text="Initializing...")
        
        # Log the action
        self.logger.info(f"Starting port scan of {host} with {len(ports_to_scan)} ports")
        
        # Run scan with progress updates
        self.port_scan_result = scan_ports(host, ports_to_scan, self.update_port_scan_progress)

    def update_port_scan_progress(self, result):
        """Update the UI with current port scan progress"""
        # Update progress bar
        self.port_scan_progress_bar.set(result.progress / 100)
        
        # Update status
        if result.current_port:
            self.port_scan_status_label.configure(text=f"{result.status} (Port: {result.current_port})")
        else:
            self.port_scan_status_label.configure(text=result.status)
        
        # If finished, update results
        if result.finished:
            if result.error:
                self.output_textbox.delete("1.0", "end")
                self.output_textbox.insert("end", f"Error during port scan: {result.error}")
                self.logger.error(f"Port scan failed: {result.error}")
            else:
                self.output_textbox.delete("1.0", "end")
                formatted_results = format_scan_results(result)
                self.output_textbox.insert("end", formatted_results)
                self.logger.info(f"Port scan completed with {len(result.open_ports)} open ports found")
            
            # Re-enable the button
            self.port_scan_button.configure(state="normal", text="Start Scan")

    def show_ssh_terminal_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="SSH Terminal", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create connection frame
        conn_frame = ctk.CTkFrame(self.content_frame)
        conn_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        conn_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)  # Equal weight for 4 columns
        
        # Host input
        host_label = ctk.CTkLabel(conn_frame, text="Host:")
        host_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        self.ssh_host_entry = ctk.CTkEntry(conn_frame)
        self.ssh_host_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # Port input
        port_label = ctk.CTkLabel(conn_frame, text="Port:")
        port_label.grid(row=0, column=2, padx=10, pady=10, sticky="e")
        
        self.ssh_port_entry = ctk.CTkEntry(conn_frame, width=80)
        self.ssh_port_entry.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        self.ssh_port_entry.insert(0, "22")
        
        # Username input
        username_label = ctk.CTkLabel(conn_frame, text="Username:")
        username_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        
        self.ssh_username_entry = ctk.CTkEntry(conn_frame)
        self.ssh_username_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        # Password input
        password_label = ctk.CTkLabel(conn_frame, text="Password:")
        password_label.grid(row=1, column=2, padx=10, pady=10, sticky="e")
        
        self.ssh_password_entry = ctk.CTkEntry(conn_frame, show="*")
        self.ssh_password_entry.grid(row=1, column=3, padx=10, pady=10, sticky="ew")
        
        # Auth type selection (password vs key file)
        auth_label = ctk.CTkLabel(conn_frame, text="Authentication:")
        auth_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
        
        self.ssh_auth_var = ctk.StringVar(value="password")
        
        auth_frame = ctk.CTkFrame(conn_frame, fg_color="transparent")
        auth_frame.grid(row=2, column=1, columnspan=3, padx=10, pady=10, sticky="w")
        
        self.password_radio = ctk.CTkRadioButton(auth_frame, text="Password", 
                                             variable=self.ssh_auth_var, value="password",
                                             command=self.toggle_ssh_auth_method)
        self.password_radio.grid(row=0, column=0, padx=(0, 20))
        
        self.key_radio = ctk.CTkRadioButton(auth_frame, text="Key File", 
                                          variable=self.ssh_auth_var, value="key",
                                          command=self.toggle_ssh_auth_method)
        self.key_radio.grid(row=0, column=1)
        
        # Key file selector
        self.key_frame = ctk.CTkFrame(conn_frame, fg_color="transparent")
        self.key_frame.grid(row=3, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="ew")
        self.key_frame.grid_columnconfigure(1, weight=1)
        
        key_file_label = ctk.CTkLabel(self.key_frame, text="Key File:")
        key_file_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        self.ssh_key_entry = ctk.CTkEntry(self.key_frame)
        self.ssh_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        self.ssh_key_button = ctk.CTkButton(self.key_frame, text="Browse", command=self.browse_key_file, width=80)
        self.ssh_key_button.grid(row=0, column=2, padx=10, pady=10)
        
        # Initially hide key file selector
        self.key_frame.grid_remove()
        
        # Connect/Disconnect buttons
        button_frame = ctk.CTkFrame(conn_frame)
        button_frame.grid(row=4, column=0, columnspan=4, padx=10, pady=(10, 10), sticky="ew")
        button_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Set up the connection attribute and buttons
        self.ssh_connection = SSHConnection()
        
        self.ssh_connect_button = ctk.CTkButton(button_frame, text="Connect", 
                                             command=self.connect_ssh, width=120)
        self.ssh_connect_button.grid(row=0, column=0, padx=10, pady=10)
        
        self.ssh_disconnect_button = ctk.CTkButton(button_frame, text="Disconnect", 
                                                command=self.disconnect_ssh, width=120,
                                                state="disabled")
        self.ssh_disconnect_button.grid(row=0, column=1, padx=10, pady=10)
        
        # Terminal output area
        terminal_frame = ctk.CTkFrame(self.content_frame)
        terminal_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="nsew")
        terminal_frame.grid_columnconfigure(0, weight=1)
        terminal_frame.grid_rowconfigure(0, weight=1)
        
        self.terminal_textbox = ctk.CTkTextbox(terminal_frame, height=300, font=("Courier", 12))
        self.terminal_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.terminal_textbox.insert("1.0", "SSH Terminal Ready. Connect to a server to begin.\n")
        self.terminal_textbox.configure(state="disabled")  # Make read-only initially
        
        # Command input area
        command_frame = ctk.CTkFrame(self.content_frame)
        command_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        command_frame.grid_columnconfigure(0, weight=1)
        
        self.command_entry = ctk.CTkEntry(command_frame, font=("Courier", 12))
        self.command_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.command_entry.configure(state="disabled")  # Disable until connected
        self.command_entry.bind("<Return>", self.send_command)
        
        self.send_button = ctk.CTkButton(command_frame, text="Send", 
                                       command=lambda: self.send_command(None), width=80,
                                       state="disabled")
        self.send_button.grid(row=0, column=1, padx=10, pady=10)
        
        # Configure content frame to expand properly
        self.content_frame.grid_rowconfigure(2, weight=1)

    def toggle_ssh_auth_method(self):
        """Toggle between password and key file authentication methods."""
        if self.ssh_auth_var.get() == "password":
            self.key_frame.grid_remove()
            self.ssh_password_entry.configure(state="normal")
        else:
            self.key_frame.grid()
            self.ssh_password_entry.configure(state="disabled")

    def browse_key_file(self):
        """Open a file dialog to select an SSH key file."""
        from tkinter import filedialog
        
        key_file = filedialog.askopenfilename(
            title="Select SSH Key File",
            filetypes=(("All Files", "*.*"), ("PEM Files", "*.pem"), ("PPK Files", "*.ppk"))
        )
        
        if key_file:
            self.ssh_key_entry.delete(0, "end")
            self.ssh_key_entry.insert(0, key_file)

    def append_to_terminal(self, data):
        """Append data to the terminal output."""
        self.terminal_textbox.configure(state="normal")
        self.terminal_textbox.insert("end", data)
        self.terminal_textbox.see("end")  # Scroll to the end
        self.terminal_textbox.configure(state="disabled")

    def connect_ssh(self):
        """Connect to the SSH server."""
        host = self.ssh_host_entry.get()
        
        try:
            port = int(self.ssh_port_entry.get())
        except ValueError:
            port = 22
            self.ssh_port_entry.delete(0, "end")
            self.ssh_port_entry.insert(0, "22")
        
        username = self.ssh_username_entry.get()
        
        # Validate inputs
        if not host or not username:
            self.append_to_terminal("Error: Host and username are required\n")
            return
        
        # Set up connection parameters based on authentication method
        password = None
        key_filename = None
        
        if self.ssh_auth_var.get() == "password":
            password = self.ssh_password_entry.get()
            if not password:
                self.append_to_terminal("Error: Password is required\n")
                return
        else:
            key_filename = self.ssh_key_entry.get()
            if not key_filename:
                self.append_to_terminal("Error: Key file is required\n")
                return
        
        # Clear terminal and update UI
        self.terminal_textbox.configure(state="normal")
        self.terminal_textbox.delete("1.0", "end")
        self.terminal_textbox.insert("1.0", f"Connecting to {host}:{port} as {username}...\n")
        self.terminal_textbox.configure(state="disabled")
        
        self.ssh_connect_button.configure(state="disabled")
        
        # Set the output callback
        self.ssh_connection.output_callback = self.append_to_terminal
        
        # Connect in a separate thread to avoid freezing the UI
        def connect_thread():
            success = self.ssh_connection.connect(host, port, username, password, key_filename)
            
            # Update UI in the main thread
            self.after(0, lambda: self._update_after_connect(success))
        
        threading.Thread(target=connect_thread, daemon=True).start()

    def _update_after_connect(self, success):
        """Update UI after connection attempt."""
        if success:
            self.ssh_disconnect_button.configure(state="normal")
            self.command_entry.configure(state="normal")
            self.send_button.configure(state="normal")
            self.append_to_terminal("Connected. You can now send commands.\n")
        else:
            self.ssh_connect_button.configure(state="normal")
            self.append_to_terminal("Connection failed.\n")

    def disconnect_ssh(self):
        """Disconnect from the SSH server."""
        if self.ssh_connection.connected:
            self.ssh_connection.disconnect()
            
            # Update UI
            self.ssh_connect_button.configure(state="normal")
            self.ssh_disconnect_button.configure(state="disabled")
            self.command_entry.configure(state="disabled")
            self.send_button.configure(state="disabled")
            
            self.append_to_terminal("Disconnected from server.\n")

    def send_command(self, event=None):
        """Send a command to the SSH server."""
        if not self.ssh_connection.connected:
            return
        
        command = self.command_entry.get()
        if not command:
            return
        
        # Send the command
        self.ssh_connection.send_command(command)
        
        # Clear the command entry
        self.command_entry.delete(0, "end")

    def show_smtp_tester_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="SMTP Tester", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create tabview for different sections
        tabview = ctk.CTkTabview(self.content_frame)
        tabview.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="new")
        
        # Create tabs
        connection_tab = tabview.add("Connection")
        message_tab = tabview.add("Message")
        security_tab = tabview.add("Security")
        
        # Configure tab grid
        for tab in [connection_tab, message_tab, security_tab]:
            tab.grid_columnconfigure(1, weight=1)
        
        # ----- Connection Tab -----
        # Server input
        server_label = ctk.CTkLabel(connection_tab, text="SMTP Server:")
        server_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_server_entry = ctk.CTkEntry(connection_tab, width=300)
        self.smtp_server_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # Port input with dropdown
        port_label = ctk.CTkLabel(connection_tab, text="Port:")
        port_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        port_frame = ctk.CTkFrame(connection_tab, fg_color="transparent")
        port_frame.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        port_frame.grid_columnconfigure(1, weight=1)
        
        self.smtp_port_entry = ctk.CTkEntry(port_frame, width=80)
        self.smtp_port_entry.grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.smtp_port_entry.insert(0, "587")  # Default port for STARTTLS
        
        # Add port selection dropdown
        common_ports = get_common_smtp_ports()
        port_values = [f"{port} - {desc}" for port, desc in common_ports]
        
        self.port_dropdown = ctk.CTkOptionMenu(
            port_frame,
            values=port_values,
            command=self.on_port_selected
        )
        self.port_dropdown.grid(row=0, column=1, sticky="w")
        self.port_dropdown.set("Select common port")
        
        # Timeout input
        timeout_label = ctk.CTkLabel(connection_tab, text="Timeout (seconds):")
        timeout_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_timeout_entry = ctk.CTkEntry(connection_tab, width=80)
        self.smtp_timeout_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        self.smtp_timeout_entry.insert(0, "30")
        
        # ----- Message Tab -----
        # From address
        from_label = ctk.CTkLabel(message_tab, text="From:")
        from_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_from_entry = ctk.CTkEntry(message_tab, width=300)
        self.smtp_from_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.smtp_from_entry.insert(0, "sender@example.com")
        
        # To address
        to_label = ctk.CTkLabel(message_tab, text="To:")
        to_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_to_entry = ctk.CTkEntry(message_tab, width=300)
        self.smtp_to_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.smtp_to_entry.insert(0, "recipient@example.com")
        
        # Subject
        subject_label = ctk.CTkLabel(message_tab, text="Subject:")
        subject_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_subject_entry = ctk.CTkEntry(message_tab, width=300)
        self.smtp_subject_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        self.smtp_subject_entry.insert(0, "Test Email from Network Toolkit")
        
        # Message body
        body_label = ctk.CTkLabel(message_tab, text="Message:")
        body_label.grid(row=3, column=0, padx=10, pady=10, sticky="nw")
        
        self.smtp_body_text = ctk.CTkTextbox(message_tab, height=100, width=300)
        self.smtp_body_text.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
        self.smtp_body_text.insert("1.0", "This is a test email sent from Network Toolkit SMTP Tester.")
        
        # ----- Security Tab -----
        # TLS options
        security_label = ctk.CTkLabel(security_tab, text="Connection Security:")
        security_label.grid(row=0, column=0, padx=10, pady=(20, 10), sticky="w")
        
        self.security_var = ctk.StringVar(value="starttls")
        
        security_frame = ctk.CTkFrame(security_tab, fg_color="transparent")
        security_frame.grid(row=0, column=1, padx=10, pady=(20, 10), sticky="w")
        
        self.none_radio = ctk.CTkRadioButton(security_frame, text="None (Plain Text)", 
                                          variable=self.security_var, value="none")
        self.none_radio.grid(row=0, column=0, padx=(0, 20), pady=5, sticky="w")
        
        self.starttls_radio = ctk.CTkRadioButton(security_frame, text="STARTTLS", 
                                              variable=self.security_var, value="starttls")
        self.starttls_radio.grid(row=1, column=0, padx=(0, 20), pady=5, sticky="w")
        
        self.ssl_radio = ctk.CTkRadioButton(security_frame, text="SSL/TLS", 
                                          variable=self.security_var, value="ssl")
        self.ssl_radio.grid(row=2, column=0, padx=(0, 20), pady=5, sticky="w")
        
        # Authentication
        auth_label = ctk.CTkLabel(security_tab, text="Authentication:")
        auth_label.grid(row=1, column=0, padx=10, pady=(20, 10), sticky="w")
        
        self.auth_var = ctk.BooleanVar(value=True)
        
        self.auth_checkbox = ctk.CTkCheckBox(security_tab, text="Use Authentication", 
                                          variable=self.auth_var, onvalue=True, offvalue=False,
                                          command=self.toggle_smtp_auth)
        self.auth_checkbox.grid(row=1, column=1, padx=10, pady=(20, 10), sticky="w")
        
        # Username and password
        self.auth_frame = ctk.CTkFrame(security_tab)
        self.auth_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        self.auth_frame.grid_columnconfigure(1, weight=1)
        
        username_label = ctk.CTkLabel(self.auth_frame, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_username_entry = ctk.CTkEntry(self.auth_frame, width=300)
        self.smtp_username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        password_label = ctk.CTkLabel(self.auth_frame, text="Password:")
        password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.smtp_password_entry = ctk.CTkEntry(self.auth_frame, show="*", width=300)
        self.smtp_password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        # Create test button frame
        test_frame = ctk.CTkFrame(self.content_frame)
        test_frame.grid(row=2, column=0, padx=20, pady=(10, 10), sticky="ew")
        test_frame.grid_columnconfigure(1, weight=1)
        
        # Test button
        self.smtp_test_button = ctk.CTkButton(test_frame, text="Send Test Email", 
                                           command=self.execute_smtp_test, width=150)
        self.smtp_test_button.grid(row=0, column=0, padx=(20, 10), pady=10, sticky="w")
        
        # Status label
        self.smtp_status_label = ctk.CTkLabel(test_frame, text="Ready")
        self.smtp_status_label.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Results:")
        output_label.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=250)
        self.output_textbox.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(4, weight=1)
        
        # Initial message
        self.output_textbox.insert("1.0", "Configure SMTP settings and click 'Send Test Email' to test.")
        
        # Set the active tab
        tabview.set("Connection")

    def on_port_selected(self, selection):
        """Handle port selection from dropdown"""
        if selection.startswith("Select"):
            return
        
        port = selection.split(" - ")[0]
        self.smtp_port_entry.delete(0, "end")
        self.smtp_port_entry.insert(0, port)
        
        # Auto-select security method based on port
        if port == "25":
            self.security_var.set("none")
        elif port == "465":
            self.security_var.set("ssl")
        elif port == "587" or port == "2525":
            self.security_var.set("starttls")

    def toggle_smtp_auth(self):
        """Toggle SMTP authentication on/off"""
        if self.auth_var.get():
            self.auth_frame.grid()
        else:
            self.auth_frame.grid_remove()

    def execute_smtp_test(self):
        """Execute the SMTP test"""
        # Get server details
        server = self.smtp_server_entry.get()
        if not server:
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: SMTP server is required")
            return
        
        try:
            port = int(self.smtp_port_entry.get())
        except ValueError:
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: Invalid port number")
            return
        
        # Get message details
        from_address = self.smtp_from_entry.get()
        to_address = self.smtp_to_entry.get()
        subject = self.smtp_subject_entry.get()
        body = self.smtp_body_text.get("1.0", "end-1c")
        
        if not from_address or not to_address:
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: From and To addresses are required")
            return
        
        # Get security settings
        security = self.security_var.get()
        use_tls = security == "starttls"
        use_ssl = security == "ssl"
        
        # Get authentication settings
        use_auth = self.auth_var.get()
        username = self.smtp_username_entry.get() if use_auth else None
        password = self.smtp_password_entry.get() if use_auth else None
        
        if use_auth and (not username or not password):
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("end", "Error: Username and password are required for authentication")
            return
        
        # Clear output and update UI
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", f"Testing SMTP connection to {server}:{port}...\n")
        self.smtp_test_button.configure(state="disabled")
        self.smtp_status_label.configure(text="Testing...")
        
        # Log the action
        self.logger.info(f"Starting SMTP test to {server}:{port}")
        
        # Run the test
        self.smtp_test_result = send_test_email(
            server, port, 
            from_address, to_address, 
            subject, body,
            use_tls, use_ssl,
            username, password,
            self.update_smtp_test_progress
        )

    def update_smtp_test_progress(self, result):
        """Update the UI with current SMTP test progress"""
        # Update status
        self.smtp_status_label.configure(text=result.status)
        
        # Update results
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("end", format_smtp_test_results(result))
        
        # Scroll to the end
        self.output_textbox.see("end")
        
        # If finished, re-enable the button
        if result.finished:
            self.smtp_test_button.configure(state="normal")
            status_text = "Success" if result.success else "Failed"
            self.smtp_status_label.configure(text=status_text)
            self.logger.info(f"SMTP test completed: {status_text}")

    def show_mail_header_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Email Header Analyzer", font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create control frame
        control_frame = ctk.CTkFrame(self.content_frame)
        control_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="new")
        control_frame.grid_columnconfigure(0, weight=1)
        
        # Instructions
        instructions = (
            "Paste email headers below to analyze them. Email headers contain information about the "
            "delivery path, authentication results, and other metadata that can help troubleshoot "
            "email delivery issues or identify potential phishing attempts."
        )
        
        instructions_label = ctk.CTkLabel(control_frame, text=instructions, wraplength=800, justify="left")
        instructions_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Input area for headers
        input_frame = ctk.CTkFrame(control_frame)
        input_frame.grid(row=1, column=0, padx=20, pady=(10, 10), sticky="new")
        input_frame.grid_columnconfigure(0, weight=1)
        
        # Header input area
        self.header_input = ctk.CTkTextbox(input_frame, height=200, font=("Courier", 12))
        self.header_input.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Buttons
        button_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        button_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")
        
        self.analyze_button = ctk.CTkButton(button_frame, text="Analyze Headers", 
                                          command=self.analyze_headers, width=150)
        self.analyze_button.grid(row=0, column=0, padx=(0, 10), pady=10, sticky="w")
        
        self.load_example_button = ctk.CTkButton(button_frame, text="Load Example", 
                                              command=self.load_example_headers, width=150)
        self.load_example_button.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        self.clear_button = ctk.CTkButton(button_frame, text="Clear", 
                                        command=self.clear_headers, width=150)
        self.clear_button.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        
        # Results display
        results_label = ctk.CTkLabel(self.content_frame, text="Analysis Results:", font=ctk.CTkFont(weight="bold"))
        results_label.grid(row=2, column=0, padx=20, pady=(0, 5), sticky="w")
        
        self.results_textbox = ctk.CTkTextbox(self.content_frame, height=300, font=("Courier", 12))
        self.results_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)
        
        # Initial message
        self.results_textbox.insert("1.0", "Paste email headers and click 'Analyze Headers' to begin.\n"
                                  "You can also click 'Load Example' to see a demonstration.")

    def analyze_headers(self):
        """Analyze the email headers from the input area"""
        header_text = self.header_input.get("1.0", "end-1c")
        
        if not header_text.strip():
            self.results_textbox.delete("1.0", "end")
            self.results_textbox.insert("end", "Error: Please enter email headers to analyze")
            return
        
        # Log the action
        self.logger.info("Starting email header analysis")
        
        # Analyze headers
        result = parse_email_headers(header_text)
        
        # Format and display results
        self.results_textbox.delete("1.0", "end")
        formatted_results = format_header_analysis(result)
        self.results_textbox.insert("end", formatted_results)
        
        self.logger.info("Email header analysis completed")

    def load_example_headers(self):
        """Load example email headers"""
        self.header_input.delete("1.0", "end")
        self.header_input.insert("end", get_example_header())
        
        # Automatically analyze the example
        self.analyze_headers()

    def clear_headers(self):
        """Clear the header input area"""
        self.header_input.delete("1.0", "end")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.insert("1.0", "Paste email headers and click 'Analyze Headers' to begin.\n"
                                  "You can also click 'Load Example' to see a demonstration.")

    def show_packet_analyzer_tool(self):
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        if not SCAPY_AVAILABLE:
            # Show error message when scapy is not available
            title = ctk.CTkLabel(self.content_frame, text="Network Packet Analyzer", 
                              font=ctk.CTkFont(size=18, weight="bold"))
            title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
            
            error_frame = ctk.CTkFrame(self.content_frame)
            error_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
            
            error_msg = ("The Scapy library is required for packet analysis but is not installed.\n"
                        "Please install it with: pip install scapy")
            
            error_label = ctk.CTkLabel(error_frame, text=error_msg, text_color=("red", "red"))
            error_label.grid(row=0, column=0, padx=20, pady=20)
            
            return
        
        # Add tool title
        title = ctk.CTkLabel(self.content_frame, text="Network Packet Analyzer", 
                          font=ctk.CTkFont(size=18, weight="bold"))
        title.grid(row=0, column=0, padx=20, pady=(20, 15), sticky="w")
        
        # Create control frame
        control_frame = ctk.CTkFrame(self.content_frame)
        control_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="new")
        control_frame.grid_columnconfigure(1, weight=1)
        
        # Warning message
        warning_text = ("WARNING: Packet capturing requires administrative/root privileges and may be "
                       "against network policies in some organizations. Only capture packets on "
                       "networks you own or have permission to monitor.")
        
        warning_label = ctk.CTkLabel(control_frame, text=warning_text, 
                                   text_color=("red", "red"), wraplength=800)
        warning_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(10, 10), sticky="w")
        
        # Interface selection
        interface_label = ctk.CTkLabel(control_frame, text="Interface:")
        interface_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        # Get available interfaces
        interfaces = get_available_interfaces()
        interfaces.insert(0, "All Interfaces")
        
        self.interface_dropdown = ctk.CTkOptionMenu(
            control_frame,
            values=interfaces,
            width=300
        )
        self.interface_dropdown.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.interface_dropdown.set(interfaces[0])
        
        # Filter string
        filter_label = ctk.CTkLabel(control_frame, text="Filter:")
        filter_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        
        self.filter_entry = ctk.CTkEntry(control_frame, width=300)
        self.filter_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        
        # Filter examples
        filter_examples_label = ctk.CTkLabel(control_frame, 
                                          text="Examples: 'tcp port 80', 'host 192.168.1.1', 'icmp'", 
                                          font=("", 12))
        filter_examples_label.grid(row=3, column=1, padx=10, pady=(0, 10), sticky="w")
        
        # Packet limit
        limit_label = ctk.CTkLabel(control_frame, text="Packet Limit:")
        limit_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
        
        self.limit_entry = ctk.CTkEntry(control_frame, width=100)
        self.limit_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")
        self.limit_entry.insert(0, "1000")
        
        # Capture control buttons
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        
        self.start_capture_button = ctk.CTkButton(button_frame, text="Start Capture", 
                                               command=self.start_packet_capture, width=150)
        self.start_capture_button.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")
        
        self.stop_capture_button = ctk.CTkButton(button_frame, text="Stop Capture", 
                                              command=self.stop_packet_capture, width=150,
                                              state="disabled")
        self.stop_capture_button.grid(row=0, column=1, padx=5, pady=10, sticky="w")
        
        self.clear_button = ctk.CTkButton(button_frame, text="Clear", 
                                        command=self.clear_packet_capture, width=150)
        self.clear_button.grid(row=0, column=2, padx=5, pady=10, sticky="w")
        
        # Stats label
        self.stats_label = ctk.CTkLabel(button_frame, text="Ready")
        self.stats_label.grid(row=0, column=3, padx=(20, 10), pady=10, sticky="w")
        
        # Create notebook for packets and statistics
        self.packet_notebook = ctk.CTkTabview(self.content_frame)
        self.packet_notebook.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(2, weight=1)
        
        # Create tabs
        packets_tab = self.packet_notebook.add("Packets")
        stats_tab = self.packet_notebook.add("Statistics")
        
        # Configure tab grid
        packets_tab.grid_columnconfigure(0, weight=1)
        packets_tab.grid_rowconfigure(0, weight=1)
        stats_tab.grid_columnconfigure(0, weight=1)
        stats_tab.grid_rowconfigure(0, weight=1)
        
        # Add packet list to packets tab
        self.packet_listbox = ctk.CTkTextbox(packets_tab, font=("Courier", 12))
        self.packet_listbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Add statistics display to stats tab
        self.stats_textbox = ctk.CTkTextbox(stats_tab, font=("Courier", 12))
        self.stats_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Set up packet capture session
        self.packet_session = PacketCaptureSession()
        
        # Set active tab
        self.packet_notebook.set("Packets")
        
        # Initial messages
        self.packet_listbox.insert("1.0", "Ready to capture packets. Click 'Start Capture' to begin.\n")
        self.stats_textbox.insert("1.0", "Capture statistics will appear here.\n")

    def start_packet_capture(self):
        """Start the packet capture."""
        # Get interface
        interface = self.interface_dropdown.get()
        if interface == "All Interfaces":
            interface = None
        
        # Get filter string
        filter_str = self.filter_entry.get()
        if not filter_str.strip():
            filter_str = None
        
        # Get packet limit
        try:
            max_packets = int(self.limit_entry.get())
            if max_packets < 1:
                max_packets = 1000
                self.limit_entry.delete(0, "end")
                self.limit_entry.insert(0, "1000")
        except ValueError:
            max_packets = 1000
            self.limit_entry.delete(0, "end")
            self.limit_entry.insert(0, "1000")
        
        # Clear previous capture
        self.clear_packet_capture()
        
        # Start the capture
        self.packet_listbox.insert("end", f"Starting packet capture on {interface or 'all interfaces'}"
                                 f"{' with filter: ' + filter_str if filter_str else ''}...\n")
        
        success = self.packet_session.start_capture(
            interface=interface,
            filter_str=filter_str,
            max_packets=max_packets,
            packet_callback=self.update_packet_list,
            stats_callback=self.update_capture_stats
        )
        
        if success:
            self.start_capture_button.configure(state="disabled")
            self.stop_capture_button.configure(state="normal")
            self.stats_label.configure(text="Capturing...")
            self.logger.info(f"Started packet capture on {interface or 'all interfaces'}")
        else:
            self.packet_listbox.insert("end", f"Error starting capture: {self.packet_session.error}\n")
            self.logger.error(f"Error starting packet capture: {self.packet_session.error}")

    def stop_packet_capture(self):
        """Stop the packet capture."""
        if self.packet_session.running:
            self.packet_session.stop_capture()
            self.packet_listbox.insert("end", "Capture stopped.\n")
            self.stats_label.configure(text="Stopped")
            self.start_capture_button.configure(state="normal")
            self.stop_capture_button.configure(state="disabled")
            self.logger.info("Stopped packet capture")

    def clear_packet_capture(self):
        """Clear the packet capture display."""
        self.packet_listbox.delete("1.0", "end")
        self.stats_textbox.delete("1.0", "end")
        self.packet_listbox.insert("1.0", "Ready to capture packets. Click 'Start Capture' to begin.\n")
        self.stats_textbox.insert("1.0", "Capture statistics will appear here.\n")
        self.stats_label.configure(text="Ready")

    def update_packet_list(self, packet, session):
        """Update the packet list with a new packet."""
        packet_str = format_packet(packet, session.packet_count)
        self.packet_listbox.configure(state="normal")
        self.packet_listbox.insert("end", f"\n{packet_str}\n{'-' * 40}\n")
        self.packet_listbox.see("end")
        self.packet_listbox.configure(state="disabled")
        
        # Update packet count in stats label
        self.stats_label.configure(text=f"Captured: {session.packet_count}")

    def update_capture_stats(self, session):
        """Update the statistics display."""
        stats_str = format_capture_stats(session)
        self.stats_textbox.configure(state="normal")
        self.stats_textbox.delete("1.0", "end")
        self.stats_textbox.insert("1.0", stats_str)
        self.stats_textbox.configure(state="disabled")