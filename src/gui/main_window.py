import customtkinter as ctk
import threading
from ..tools.ping import ping_host
from ..tools.dns_lookup import dns_lookup, get_common_record_types
from ..utils.logger import setup_logger

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
        
        self.tracert_button = ctk.CTkButton(self.sidebar_frame, text="Traceroute", state="disabled")
        self.tracert_button.grid(row=3, column=0, padx=20, pady=10)
        
        self.speedtest_button = ctk.CTkButton(self.sidebar_frame, text="Speed Test", state="disabled")
        self.speedtest_button.grid(row=4, column=0, padx=20, pady=10)
        
        self.whois_button = ctk.CTkButton(self.sidebar_frame, text="WHOIS", state="disabled")
        self.whois_button.grid(row=5, column=0, padx=20, pady=10)
        
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