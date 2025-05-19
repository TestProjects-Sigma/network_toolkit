import customtkinter as ctk
import threading
from ..tools.ping import ping_host
from ..tools.dns_lookup import dns_lookup, get_common_record_types
from ..utils.logger import setup_logger
from ..tools.traceroute import traceroute
from ..tools.speedtest import run_speed_test, format_speed_test_results
from ..tools.whois_lookup import whois_lookup
from ..tools.port_scanner import scan_ports, get_common_ports, format_scan_results


class NetworkToolkitApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Set up logging
        self.logger = setup_logger("network_toolkit", "logs/app.log")
        self.logger.info("Application started")
        
        # Configure window
        self.title("Network Toolkit")
        self.geometry("950x650")
        ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
        ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"
        
        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=5)
        self.grid_rowconfigure(0, weight=1)
        
        # Create sidebar frame with tools
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)
        
        # App title in sidebar
        self.app_title = ctk.CTkLabel(self.sidebar_frame, text="Network Toolkit", font=ctk.CTkFont(size=20, weight="bold"))
        self.app_title.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Tools buttons
        self.ping_button = ctk.CTkButton(self.sidebar_frame, text="Ping", command=self.show_ping_tool)
        self.ping_button.grid(row=1, column=0, padx=20, pady=10)
        
        # Enable the DNS button (change state to normal)
        self.dns_button = ctk.CTkButton(self.sidebar_frame, text="DNS Lookup", command=self.show_dns_tool)
        self.dns_button.grid(row=2, column=0, padx=20, pady=10)
        
        self.tracert_button = ctk.CTkButton(self.sidebar_frame, text="Traceroute", command=self.show_traceroute_tool)
        self.tracert_button.grid(row=3, column=0, padx=20, pady=10)

        
        self.speedtest_button = ctk.CTkButton(self.sidebar_frame, text="Speed Test", command=self.show_speedtest_tool)
        self.speedtest_button.grid(row=4, column=0, padx=20, pady=10)
        
        self.whois_button = ctk.CTkButton(self.sidebar_frame, text="WHOIS", command=self.show_whois_tool)
        self.whois_button.grid(row=5, column=0, padx=20, pady=10)

        self.port_scan_button = ctk.CTkButton(self.sidebar_frame, text="Port Scanner", command=self.show_port_scanner_tool)
        self.port_scan_button.grid(row=6, column=0, padx=20, pady=10)
        
        # Main content frame
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(3, weight=1)
        
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
        
        # Create form frame with more space
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="new")
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Warning text
        warning_text = ("WARNING: Port scanning may be against the Terms of Service of your network or ISP.\n"
                      "Only scan hosts you have permission to scan.")
        
        warning_label = ctk.CTkLabel(form_frame, text=warning_text, 
                                   text_color=("red", "red"), justify="left")
        warning_label.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="w")
        
        # Host input
        host_label = ctk.CTkLabel(form_frame, text="Host:")
        host_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.port_scan_host_entry = ctk.CTkEntry(form_frame, width=300)
        self.port_scan_host_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.port_scan_host_entry.insert(0, "localhost")
        
        # Port selection section
        ports_label = ctk.CTkLabel(form_frame, text="Ports to scan:", font=ctk.CTkFont(weight="bold"))
        ports_label.grid(row=2, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="w")
        
        # Common ports checkboxes
        common_ports_frame = ctk.CTkFrame(form_frame)
        common_ports_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        common_ports_frame.grid_columnconfigure(4, weight=1)  # Make the last column expandable
        
        # Get common ports list
        common_ports = get_common_ports()
        
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
        custom_ports_label = ctk.CTkLabel(form_frame, text="Custom ports:", font=ctk.CTkFont(weight="bold"))
        custom_ports_label.grid(row=4, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="w")
        
        custom_ports_help = ctk.CTkLabel(form_frame, 
                                       text="Enter port numbers separated by commas (e.g., 8000,8080,9000)",
                                       font=ctk.CTkFont(size=12))
        custom_ports_help.grid(row=5, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="w")
        
        self.custom_ports_entry = ctk.CTkEntry(form_frame, width=300)
        self.custom_ports_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        
        # Create button frame
        button_frame = ctk.CTkFrame(form_frame)
        button_frame.grid(row=7, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="ew")
        button_frame.grid_columnconfigure(1, weight=1)
        
        # Scan button
        self.port_scan_button = ctk.CTkButton(button_frame, text="Start Scan", 
                                           command=self.execute_port_scan, width=120)
        self.port_scan_button.grid(row=0, column=0, padx=(10, 10), pady=10, sticky="w")
        
        # Progress bar and status
        self.port_scan_progress_frame = ctk.CTkFrame(button_frame)
        self.port_scan_progress_frame.grid(row=0, column=1, padx=(10, 10), pady=10, sticky="ew")
        self.port_scan_progress_frame.grid_columnconfigure(0, weight=1)
        
        self.port_scan_progress_bar = ctk.CTkProgressBar(self.port_scan_progress_frame, width=300)
        self.port_scan_progress_bar.grid(row=0, column=0, padx=10, pady=(5, 0), sticky="ew")
        self.port_scan_progress_bar.set(0)
        
        self.port_scan_status_label = ctk.CTkLabel(self.port_scan_progress_frame, text="Ready to scan")
        self.port_scan_status_label.grid(row=1, column=0, padx=10, pady=(5, 5), sticky="w")
        
        # Output text area
        output_label = ctk.CTkLabel(self.content_frame, text="Results:")
        output_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        
        self.output_textbox = ctk.CTkTextbox(self.content_frame, height=300)
        self.output_textbox.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.content_frame.grid_rowconfigure(3, weight=1)
        
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