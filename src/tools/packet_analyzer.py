import time
import threading
import socket
import struct
import ipaddress
import collections
from datetime import datetime
from ..utils.logger import get_logger

# Import scapy with error handling
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger = get_logger("packet_analyzer_tool")
    logger.error("Scapy library not found. Network Packet Analyzer will be disabled.")

if SCAPY_AVAILABLE:
    logger = get_logger("packet_analyzer_tool")

    class PacketCaptureSession:
        """Class to handle packet capture sessions"""
        def __init__(self):
            self.packets = []
            self.running = False
            self.stop_event = threading.Event()
            self.start_time = None
            self.end_time = None
            self.interface = None
            self.filter = None
            self.packet_count = 0
            self.max_packets = 1000
            self.packet_callback = None
            self.stats_callback = None
            self.protocol_stats = collections.Counter()
            self.ip_stats = collections.Counter()
            self.port_stats = collections.Counter()
            self.size_stats = {
                'min': float('inf'),
                'max': 0,
                'total': 0,
                'avg': 0
            }
            self.sniffer_thread = None
            self.error = None
            
        def start_capture(self, interface=None, filter_str=None, max_packets=1000, 
                         packet_callback=None, stats_callback=None):
            """
            Start capturing packets on the specified interface.
            
            Args:
                interface (str): Network interface to capture on (None for all)
                filter_str (str): BPF filter string (e.g. "tcp port 80")
                max_packets (int): Maximum number of packets to capture
                packet_callback (callable): Callback for new packets
                stats_callback (callable): Callback for updated statistics
                
            Returns:
                bool: True if capture started successfully, False otherwise
            """
            if self.running:
                return False
            
            self.interface = interface
            self.filter = filter_str
            self.max_packets = max_packets
            self.packet_callback = packet_callback
            self.stats_callback = stats_callback
            self.packets = []
            self.protocol_stats.clear()
            self.ip_stats.clear()
            self.port_stats.clear()
            self.size_stats = {
                'min': float('inf'),
                'max': 0,
                'total': 0,
                'avg': 0
            }
            self.packet_count = 0
            self.error = None
            self.stop_event.clear()
            
            try:
                self.running = True
                self.start_time = datetime.now()
                
                # Start sniffer in a separate thread
                self.sniffer_thread = threading.Thread(
                    target=self._run_sniffer,
                    args=(interface, filter_str, max_packets)
                )
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()
                
                logger.info(f"Started packet capture on {interface or 'all interfaces'}"
                          f"{' with filter: ' + filter_str if filter_str else ''}")
                return True
                
            except Exception as e:
                self.error = str(e)
                self.running = False
                logger.error(f"Error starting packet capture: {str(e)}")
                return False
        
        def stop_capture(self):
            """Stop the packet capture."""
            if self.running:
                self.stop_event.set()
                self.running = False
                self.end_time = datetime.now()
                logger.info("Packet capture stopped")
                
                # Update final statistics
                if self.stats_callback:
                    self.stats_callback(self)
                
                return True
            return False
        
        def _run_sniffer(self, interface, filter_str, max_packets):
            """Run the packet sniffer."""
            try:
                # Define packet handler
                def packet_handler(packet):
                    if self.stop_event.is_set() or self.packet_count >= max_packets:
                        return True  # Signal to stop sniffing
                    
                    # Process the packet
                    self._process_packet(packet)
                    
                    # Call packet callback if set
                    if self.packet_callback:
                        self.packet_callback(packet, self)
                    
                    # Call stats callback every 10 packets
                    if self.stats_callback and self.packet_count % 10 == 0:
                        self.stats_callback(self)
                    
                    # Stop if we've reached the max packet count
                    if self.packet_count >= max_packets:
                        logger.info(f"Reached maximum packet count: {max_packets}")
                        self.stop_event.set()
                        self.running = False
                        self.end_time = datetime.now()
                        return True
                    
                    return False
                
                # Start sniffing
                sniff(
                    iface=interface if interface else None,
                    filter=filter_str if filter_str else None,
                    prn=packet_handler,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    store=0  # Don't store packets in scapy's internal list
                )
                
            except Scapy_Exception as e:
                self.error = f"Scapy error: {str(e)}"
                logger.error(self.error)
                self.running = False
                
            except Exception as e:
                self.error = f"Error during packet capture: {str(e)}"
                logger.error(self.error)
                self.running = False
            
            finally:
                if self.running:
                    self.stop_capture()
        
        def _process_packet(self, packet):
            """Process a captured packet and update statistics."""
            self.packet_count += 1
            self.packets.append(packet)
            
            # Update protocol statistics
            if IP in packet:
                self.protocol_stats['IP'] += 1
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                self.ip_stats[f"SRC: {ip_src}"] += 1
                self.ip_stats[f"DST: {ip_dst}"] += 1
                
                # Update size statistics
                packet_size = len(packet)
                self.size_stats['total'] += packet_size
                self.size_stats['min'] = min(self.size_stats['min'], packet_size)
                self.size_stats['max'] = max(self.size_stats['max'], packet_size)
                self.size_stats['avg'] = self.size_stats['total'] / self.packet_count
                
                # Check for common protocols
                if TCP in packet:
                    self.protocol_stats['TCP'] += 1
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    self.port_stats[f"TCP {sport} → {dport}"] += 1
                    
                    # Check for common applications
                    if dport == 80 or sport == 80:
                        self.protocol_stats['HTTP'] += 1
                    elif dport == 443 or sport == 443:
                        self.protocol_stats['HTTPS'] += 1
                    elif dport == 22 or sport == 22:
                        self.protocol_stats['SSH'] += 1
                    elif dport == 21 or sport == 21:
                        self.protocol_stats['FTP'] += 1
                    
                elif UDP in packet:
                    self.protocol_stats['UDP'] += 1
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    self.port_stats[f"UDP {sport} → {dport}"] += 1
                    
                    # Check for common applications
                    if dport == 53 or sport == 53:
                        self.protocol_stats['DNS'] += 1
                    
                elif ICMP in packet:
                    self.protocol_stats['ICMP'] += 1
                
            elif ARP in packet:
                self.protocol_stats['ARP'] += 1
            
            elif Ether in packet:
                self.protocol_stats['Ethernet'] += 1
    
    def get_available_interfaces():
        """Get a list of available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            logger.error(f"Error getting network interfaces: {str(e)}")
            return []
    
    def format_packet(packet, index):
        """Format a packet for display."""
        result = f"Packet #{index}:\n"
        
        # Add timestamp
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        result += f"Time: {timestamp}\n"
        
        # Start with link layer
        if Ether in packet:
            eth = packet[Ether]
            result += f"Ethernet: {eth.src} → {eth.dst}, type: 0x{eth.type:04x}\n"
        
        # Add network layer
        if IP in packet:
            ip = packet[IP]
            result += f"IP: {ip.src} → {ip.dst} (TTL: {ip.ttl})\n"
            
            # Add transport layer
            if TCP in packet:
                tcp = packet[TCP]
                result += f"TCP: Port {tcp.sport} → {tcp.dport} "
                flags = []
                if tcp.flags.S:
                    flags.append("SYN")
                if tcp.flags.A:
                    flags.append("ACK")
                if tcp.flags.F:
                    flags.append("FIN")
                if tcp.flags.R:
                    flags.append("RST")
                if tcp.flags.P:
                    flags.append("PSH")
                result += f"Flags: [{' '.join(flags)}]\n"
                
                # Add application layer
                if Raw in packet:
                    data = packet[Raw].load
                    if data[:4] in [b'GET ', b'POST', b'HTTP']:
                        result += "HTTP Data Found\n"
                    elif b'\x16\x03' in data[:4]:  # TLS handshake
                        result += "TLS/SSL Data Found\n"
                
            elif UDP in packet:
                udp = packet[UDP]
                result += f"UDP: Port {udp.sport} → {udp.dport}\n"
                
                # Check for DNS
                if DNS in packet:
                    dns = packet[DNS]
                    if dns.qr == 0:  # Query
                        names = [name.decode() for name in dns.qd.qname]
                        result += f"DNS Query: {'.'.join(names)}\n"
                    else:  # Response
                        result += f"DNS Response: {dns.ancount} answers\n"
                
            elif ICMP in packet:
                icmp = packet[ICMP]
                result += f"ICMP: Type {icmp.type} Code {icmp.code}\n"
        
        elif ARP in packet:
            arp = packet[ARP]
            op = "request" if arp.op == 1 else "reply"
            result += f"ARP: {arp.psrc} → {arp.pdst} ({op})\n"
        
        # Add packet size
        result += f"Length: {len(packet)} bytes\n"
        
        return result
    
    def format_capture_stats(session):
        """Format capture statistics for display."""
        if not session.packet_count:
            return "No packets captured."
        
        result = f"PACKET CAPTURE STATISTICS\n{'-' * 60}\n"
        
        # Basic information
        result += f"Total Packets: {session.packet_count}\n"
        
        duration = "In progress..."
        if session.start_time and session.end_time:
            duration_seconds = (session.end_time - session.start_time).total_seconds()
            if duration_seconds < 60:
                duration = f"{duration_seconds:.2f} seconds"
            else:
                duration = f"{duration_seconds / 60:.2f} minutes"
        elif session.start_time:
            duration_seconds = (datetime.now() - session.start_time).total_seconds()
            if duration_seconds < 60:
                duration = f"{duration_seconds:.2f} seconds (in progress)"
            else:
                duration = f"{duration_seconds / 60:.2f} minutes (in progress)"
        
        result += f"Duration: {duration}\n"
        
        if session.interface:
            result += f"Interface: {session.interface}\n"
        else:
            result += "Interface: All interfaces\n"
        
        if session.filter:
            result += f"Filter: {session.filter}\n"
        
        # Size statistics
        if session.packet_count:
            result += f"\nPACKET SIZES:\n"
            result += f"Average: {session.size_stats['avg']:.1f} bytes\n"
            result += f"Minimum: {session.size_stats['min']} bytes\n"
            result += f"Maximum: {session.size_stats['max']} bytes\n"
            result += f"Total: {session.size_stats['total']} bytes\n"
        
        # Protocol statistics
        if session.protocol_stats:
            result += f"\nPROTOCOL DISTRIBUTION:\n"
            for protocol, count in sorted(session.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / session.packet_count) * 100
                result += f"{protocol}: {count} packets ({percentage:.1f}%)\n"
        
        # Top IP addresses
        if session.ip_stats:
            result += f"\nTOP IP ADDRESSES (TOP 10):\n"
            for ip, count in sorted(session.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / session.packet_count) * 100
                result += f"{ip}: {count} packets ({percentage:.1f}%)\n"
        
        # Top ports
        if session.port_stats:
            result += f"\nTOP PORTS (TOP 10):\n"
            for port, count in sorted(session.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / session.packet_count) * 100
                result += f"{port}: {count} packets ({percentage:.1f}%)\n"
        
        return result

else:
    # Stubs for when scapy is not available
    class PacketCaptureSession:
        def __init__(self):
            self.error = "Scapy library not installed. Please install it with 'pip install scapy'."
        
        def start_capture(self, *args, **kwargs):
            return False
        
        def stop_capture(self):
            return False
    
    def get_available_interfaces():
        return []
    
    def format_packet(packet, index):
        return "Scapy library not available."
    
    def format_capture_stats(session):
        return "Scapy library not available. Please install it with 'pip install scapy'."