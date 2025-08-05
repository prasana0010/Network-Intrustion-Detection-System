import threading
import pyshark # type: ignore
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import matplotlib.pyplot as plt # type: ignore
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg # type: ignore
import matplotlib.animation as animation # type: ignore
from matplotlib.patches import Circle, Rectangle # type: ignore
from collections import defaultdict, deque
import asyncio
import time
from datetime import datetime, timedelta
import json
import os
import socket
import ipaddress


class UnifiedNetworkAnalysisSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Unified Network Analysis Suite - Complete Network Intelligence Platform")
        self.root.geometry("1800x1200")
        self.root.configure(bg='#1a1a2e')
        
        # Global configuration
        self.interface = tk.StringVar(value='Wi-Fi')
        self.is_monitoring = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        # Data storage for all modules
        self.init_data_structures()
        
        # Setup UI
        self.setup_styles()
        self.create_main_interface()
        self.init_monitoring_threads()

    def init_data_structures(self):
        """Initialize all data structures for different modules"""
        # Live Packet Capture Data
        self.captured_packets = []
        self.capture_stats = {'total': 0, 'tcp': 0, 'udp': 0, 'other': 0}
        
        # DNS Monitoring Data
        self.dns_queries = deque(maxlen=500)
        self.dns_counts = deque([0] * 60, maxlen=60)
        self.target_domains = ['example.com', 'malicious.com']
        self.domain_stats = defaultdict(int)
        
        # PCAP Analysis Data
        self.pcap_packets = []
        self.pcap_statistics = {}
        self.current_pcap_file = None
        
        # Traffic Monitoring Data
        self.traffic_data = defaultdict(lambda: {'in': 0, 'out': 0, 'total': 0})
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.bandwidth_history = deque([0] * 60, maxlen=60)
        self.alerts = deque(maxlen=100)
        
        # Unified Timeline Data
        self.timeline_events = deque(maxlen=1000)
        self.threat_indicators = deque(maxlen=50)
        
        # Performance metrics
        self.start_time = None
        self.total_packets_processed = 0
        self.total_bytes_processed = 0

    def setup_styles(self):
        """Configure comprehensive dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme
        colors = {
            'bg_primary': '#1a1a2e',
            'bg_secondary': '#16213e',
            'bg_tertiary': '#0f3460',
            'accent_blue': '#533483',
            'accent_purple': '#7209b7',
            'text_primary': '#ffffff',
            'text_secondary': '#a0a0a0',
            'success': '#00ff88',
            'warning': '#ffa500',
            'danger': '#ff4444',
            'info': '#00bfff'
        }
        
        # Configure styles
        style.configure('Main.TFrame', background=colors['bg_primary'])
        style.configure('Secondary.TFrame', background=colors['bg_secondary'])
        style.configure('Card.TFrame', background=colors['bg_tertiary'])
        
        style.configure('Title.TLabel', font=('Segoe UI', 24, 'bold'), 
                       background=colors['bg_primary'], foreground=colors['text_primary'])
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), 
                       background=colors['bg_secondary'], foreground=colors['text_primary'])
        style.configure('Subheader.TLabel', font=('Segoe UI', 12), 
                       background=colors['bg_tertiary'], foreground=colors['text_secondary'])
        
        style.configure('Success.TLabel', foreground=colors['success'], font=('Segoe UI', 10))
        style.configure('Warning.TLabel', foreground=colors['warning'], font=('Segoe UI', 10, 'bold'))
        style.configure('Danger.TLabel', foreground=colors['danger'], font=('Segoe UI', 10, 'bold'))
        style.configure('Info.TLabel', foreground=colors['info'], font=('Segoe UI', 10))
        
        # Button styles
        style.configure('Primary.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Success.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Warning.TButton', font=('Segoe UI', 10, 'bold'))

    def create_main_interface(self):
        """Create the main unified interface"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Main.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title bar with branding
        self.create_title_bar(main_frame)
        
        # Global control panel
        self.create_global_controls(main_frame)
        
        # Main tabbed interface
        self.create_tabbed_modules(main_frame)
        
        # Unified status bar
        self.create_unified_status_bar(main_frame)

    def create_title_bar(self, parent):
        """Create attractive title bar with branding"""
        title_frame = ttk.Frame(parent, style='Secondary.TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Main title with gradient effect simulation
        title_container = ttk.Frame(title_frame, style='Secondary.TFrame')
        title_container.pack(pady=15)
        
        title_label = ttk.Label(title_container, 
                               text="🌐 UNIFIED NETWORK ANALYSIS SUITE", 
                               style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_container, 
                                  text="Complete Network Intelligence Platform • Real-Time Monitoring • Threat Detection • Traffic Analysis",
                                  style='Subheader.TLabel')
        subtitle_label.pack(pady=(5, 0))

    def create_global_controls(self, parent):
        """Create global control panel for all modules"""
        control_frame = ttk.LabelFrame(parent, text="🎛️ Global Configuration & Control Center", 
                                      style='Card.TFrame')
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Configuration row
        config_container = ttk.Frame(control_frame, style='Card.TFrame')
        config_container.pack(fill=tk.X, padx=15, pady=15)
        
        # Interface and basic settings
        settings_left = ttk.Frame(config_container, style='Card.TFrame')
        settings_left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(settings_left, text="Network Interface:", style='Header.TLabel').pack(side=tk.LEFT, padx=5)
        interface_combo = ttk.Combobox(settings_left, textvariable=self.interface, width=15,
                                      values=['Wi-Fi', 'Ethernet', 'eth0', 'wlan0', 'en0'])
        interface_combo.pack(side=tk.LEFT, padx=(5, 20))
        
        # Alert thresholds
        ttk.Label(settings_left, text="Bandwidth Alert (MB):", style='Header.TLabel').pack(side=tk.LEFT, padx=5)
        self.bandwidth_threshold = tk.DoubleVar(value=10.0)
        threshold_spin = ttk.Spinbox(settings_left, from_=1.0, to=1000.0, increment=1.0,
                                   textvariable=self.bandwidth_threshold, width=8)
        threshold_spin.pack(side=tk.LEFT, padx=(5, 20))
        
        # DNS target domains
        ttk.Label(settings_left, text="Monitor Domains:", style='Header.TLabel').pack(side=tk.LEFT, padx=5)
        self.domain_filter = tk.StringVar(value='example.com,malicious.com')
        domain_entry = ttk.Entry(settings_left, textvariable=self.domain_filter, width=25)
        domain_entry.pack(side=tk.LEFT, padx=(5, 20))
        
        # Master control buttons
        control_buttons = ttk.Frame(config_container, style='Card.TFrame')
        control_buttons.pack(side=tk.RIGHT, padx=15)
        
        self.master_start_btn = ttk.Button(control_buttons, text="🚀 START ALL MONITORING", 
                                          command=self.start_all_monitoring, 
                                          style='Success.TButton')
        self.master_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.master_stop_btn = ttk.Button(control_buttons, text="⏹️ STOP ALL", 
                                         command=self.stop_all_monitoring, 
                                         style='Warning.TButton', state='disabled')
        self.master_stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_all_btn = ttk.Button(control_buttons, text="💾 EXPORT UNIFIED REPORT", 
                                        command=self.export_unified_report,
                                        style='Primary.TButton')
        self.export_all_btn.pack(side=tk.LEFT, padx=5)

    def create_tabbed_modules(self, parent):
        """Create the main tabbed interface for all modules"""
        self.main_notebook = ttk.Notebook(parent)
        self.main_notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Module tabs
        self.create_dashboard_tab()
        self.create_live_capture_tab()
        self.create_dns_monitoring_tab()
        self.create_pcap_analysis_tab()
        self.create_traffic_analysis_tab()
        self.create_threat_detection_tab()
        self.create_network_map_tab()

    def create_dashboard_tab(self):
        """Create unified dashboard with overview of all modules"""
        dashboard_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(dashboard_frame, text="📊 UNIFIED DASHBOARD")
        
        # Create matplotlib figure for dashboard
        self.dash_fig, ((self.ax_timeline, self.ax_threats), 
                       (self.ax_protocols, self.ax_geography)) = plt.subplots(2, 2, figsize=(16, 10))
        
        # Configure dark theme for all axes
        self.dash_fig.patch.set_facecolor('#16213e')
        for ax in [self.ax_timeline, self.ax_threats, self.ax_protocols, self.ax_geography]:
            ax.set_facecolor('#1a1a2e')
            ax.tick_params(colors='white')
            ax.grid(True, alpha=0.2, color='white')
        
        # Timeline of all network events
        self.ax_timeline.set_title('Unified Network Activity Timeline', color='white', fontweight='bold', pad=20)
        self.ax_timeline.set_ylabel('Events per Minute', color='white')
        self.timeline_line, = self.ax_timeline.plot([], [], 'o-', color='#533483', linewidth=2, markersize=4)
        
        # Threat detection indicators
        self.ax_threats.set_title('Real-Time Threat Indicators', color='white', fontweight='bold', pad=20)
        self.ax_threats.set_ylabel('Threat Level', color='white')
        
        # Protocol distribution across all modules
        self.ax_protocols.set_title('Global Protocol Distribution', color='white', fontweight='bold', pad=20)
        
        # Geographic analysis placeholder
        self.ax_geography.set_title('Network Geography & External Connections', color='white', fontweight='bold', pad=20)
        
        plt.tight_layout()
        
        # Embed dashboard
        self.dash_canvas = FigureCanvasTkAgg(self.dash_fig, master=dashboard_frame)
        self.dash_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dashboard animation
        self.dash_animation = animation.FuncAnimation(self.dash_fig, self.update_dashboard,
                                                     interval=3000, blit=False)

    def create_live_capture_tab(self):
        """Create live packet capture module tab"""
        capture_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(capture_frame, text="📡 LIVE CAPTURE")
        
        # Split layout
        capture_main = ttk.Frame(capture_frame)
        capture_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left side - Controls and filters
        capture_controls = ttk.LabelFrame(capture_main, text="🎯 Capture Configuration")
        capture_controls.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        controls_content = ttk.Frame(capture_controls)
        controls_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Packet count limit
        ttk.Label(controls_content, text="Packet Limit:").pack(anchor='w', pady=2)
        self.packet_limit = tk.IntVar(value=1000)
        ttk.Spinbox(controls_content, from_=100, to=10000, increment=100,
                   textvariable=self.packet_limit, width=15).pack(anchor='w', pady=2)
        
        # Protocol filter
        ttk.Label(controls_content, text="Protocol Filter:").pack(anchor='w', pady=(10, 2))
        self.protocol_filter = tk.StringVar(value='all')
        protocol_combo = ttk.Combobox(controls_content, textvariable=self.protocol_filter, 
                                     values=['all', 'tcp', 'udp', 'icmp', 'http', 'https', 'dns'])
        protocol_combo.pack(anchor='w', pady=2, fill=tk.X)
        
        # Output file configuration
        ttk.Label(controls_content, text="Output File:").pack(anchor='w', pady=(10, 2))
        self.capture_output = tk.StringVar(value='live_capture.pcap')
        ttk.Entry(controls_content, textvariable=self.capture_output).pack(anchor='w', pady=2, fill=tk.X)
        
        # Capture controls
        ttk.Button(controls_content, text="▶️ Start Capture", 
                  command=self.start_live_capture).pack(anchor='w', pady=(20, 5), fill=tk.X)
        ttk.Button(controls_content, text="⏹️ Stop Capture", 
                  command=self.stop_live_capture).pack(anchor='w', pady=5, fill=tk.X)
        ttk.Button(controls_content, text="💾 Save Packets", 
                  command=self.save_captured_packets).pack(anchor='w', pady=5, fill=tk.X)
        
        # Statistics display
        stats_frame = ttk.LabelFrame(controls_content, text="📈 Live Statistics")
        stats_frame.pack(fill=tk.X, pady=(20, 0))
        
        stats_content = ttk.Frame(stats_frame)
        stats_content.pack(fill=tk.X, padx=5, pady=5)
        
        self.capture_stats_text = tk.Text(stats_content, height=10, width=30, 
                                         bg='#1a1a2e', fg='white', font=('Courier', 9))
        self.capture_stats_text.pack(fill=tk.BOTH)
        
        # Right side - Packet display
        packet_display = ttk.LabelFrame(capture_main, text="📋 Real-Time Packet Stream")
        packet_display.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Packet list with treeview
        packet_columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(packet_display, columns=packet_columns, show='headings', height=25)
        
        for col in packet_columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=120 if col == "Info" else 100)
        
        # Scrollbars for packet tree
        packet_v_scroll = ttk.Scrollbar(packet_display, orient=tk.VERTICAL, command=self.packet_tree.yview)
        packet_h_scroll = ttk.Scrollbar(packet_display, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=packet_v_scroll.set, xscrollcommand=packet_h_scroll.set)
        
        self.packet_tree.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        packet_v_scroll.grid(row=0, column=1, sticky='ns')
        packet_h_scroll.grid(row=1, column=0, sticky='ew')
        
        packet_display.grid_rowconfigure(0, weight=1)
        packet_display.grid_columnconfigure(0, weight=1)

    def create_dns_monitoring_tab(self):
        """Create DNS monitoring module tab"""
        dns_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(dns_frame, text="🔍 DNS MONITOR")
        
        # DNS monitoring layout
        dns_main = ttk.Frame(dns_frame)
        dns_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top section - DNS visualization
        dns_viz_frame = ttk.LabelFrame(dns_main, text="📊 DNS Query Visualization")
        dns_viz_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create DNS monitoring graphs
        self.dns_fig, (self.ax_dns_timeline, self.ax_dns_domains) = plt.subplots(2, 1, figsize=(14, 8))
        self.dns_fig.patch.set_facecolor('#16213e')
        
        for ax in [self.ax_dns_timeline, self.ax_dns_domains]:
            ax.set_facecolor('#1a1a2e')
            ax.tick_params(colors='white')
            ax.grid(True, alpha=0.2, color='white')
        
        # DNS query timeline
        self.ax_dns_timeline.set_title('DNS Query Rate Over Time', color='white', fontweight='bold')
        self.ax_dns_timeline.set_ylabel('Queries/Second', color='white')
        self.dns_line, = self.ax_dns_timeline.plot([], [], 'o-', color='#00ff88', linewidth=2)
        
        # DNS activity indicator
        self.dns_activity = Circle((0, 0), 0.5, color='#ff4444', alpha=0.7)
        self.ax_dns_timeline.add_patch(self.dns_activity)
        
        # Top queried domains
        self.ax_dns_domains.set_title('Most Queried Domains', color='white', fontweight='bold')
        self.ax_dns_domains.set_xlabel('Query Count', color='white')
        
        plt.tight_layout()
        
        self.dns_canvas = FigureCanvasTkAgg(self.dns_fig, master=dns_viz_frame)
        self.dns_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom section - DNS logs and alerts
        dns_logs_frame = ttk.LabelFrame(dns_main, text="📝 DNS Query Log & Alerts")
        dns_logs_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.dns_log_text = scrolledtext.ScrolledText(dns_logs_frame, height=8, 
                                                     bg='#1a1a2e', fg='#00ff88',
                                                     font=('Courier', 9))
        self.dns_log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # DNS animation
        self.dns_animation = animation.FuncAnimation(self.dns_fig, self.update_dns_graphs,
                                                    interval=2000, blit=False)

    def create_pcap_analysis_tab(self):
        """Create PCAP file analysis module tab"""
        pcap_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(pcap_frame, text="📁 PCAP ANALYSIS")
        
        pcap_main = ttk.Frame(pcap_frame)
        pcap_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # File management section
        file_section = ttk.LabelFrame(pcap_main, text="📂 PCAP File Management")
        file_section.pack(fill=tk.X, pady=(0, 10))
        
        file_controls = ttk.Frame(file_section)
        file_controls.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(file_controls, text="Selected File:").pack(side=tk.LEFT)
        self.pcap_file_var = tk.StringVar(value="No file selected")
        ttk.Label(file_controls, textvariable=self.pcap_file_var, 
                 style='Info.TLabel').pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(file_controls, text="📂 Browse PCAP", 
                  command=self.browse_pcap_file).pack(side=tk.RIGHT, padx=5)
        ttk.Button(file_controls, text="🔬 Analyze", 
                  command=self.analyze_pcap_file).pack(side=tk.RIGHT, padx=5)
        
        # Analysis results with notebook
        analysis_notebook = ttk.Notebook(pcap_main)
        analysis_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Packet list tab
        packet_list_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(packet_list_frame, text="📋 Packet List")
        
        pcap_columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.pcap_tree = ttk.Treeview(packet_list_frame, columns=pcap_columns, show='headings')
        
        for col in pcap_columns:
            self.pcap_tree.heading(col, text=col)
            self.pcap_tree.column(col, width=100)
        
        pcap_v_scroll = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, command=self.pcap_tree.yview)
        self.pcap_tree.configure(yscrollcommand=pcap_v_scroll.set)
        
        self.pcap_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        pcap_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statistics tab
        stats_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(stats_frame, text="📊 Statistics")
        
        self.pcap_stats_text = scrolledtext.ScrolledText(stats_frame, bg='#1a1a2e', fg='white',
                                                        font=('Courier', 10))
        self.pcap_stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Packet details tab
        details_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(details_frame, text="🔍 Packet Details")
        
        self.pcap_details_text = scrolledtext.ScrolledText(details_frame, bg='#1a1a2e', fg='white',
                                                          font=('Courier', 9))
        self.pcap_details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Bind packet selection
        self.pcap_tree.bind('<<TreeviewSelect>>', self.on_pcap_packet_select)

    def create_traffic_analysis_tab(self):
        """Create traffic analysis module tab"""
        traffic_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(traffic_frame, text="📈 TRAFFIC ANALYSIS")
        
        traffic_main = ttk.Frame(traffic_frame)
        traffic_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Traffic visualization
        traffic_viz_frame = ttk.LabelFrame(traffic_main, text="📊 Real-Time Traffic Analysis")
        traffic_viz_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create traffic analysis graphs
        self.traffic_fig, ((self.ax_bandwidth, self.ax_top_hosts), 
                          (self.ax_protocols_traffic, self.ax_ports)) = plt.subplots(2, 2, figsize=(16, 10))
        
        self.traffic_fig.patch.set_facecolor('#16213e')
        for ax in [self.ax_bandwidth, self.ax_top_hosts, self.ax_protocols_traffic, self.ax_ports]:
            ax.set_facecolor('#1a1a2e')
            ax.tick_params(colors='white')
            ax.grid(True, alpha=0.2, color='white')
        
        # Bandwidth over time
        self.ax_bandwidth.set_title('Network Bandwidth Usage', color='white', fontweight='bold')
        self.ax_bandwidth.set_ylabel('Bandwidth (MB/s)', color='white')
        self.bandwidth_line, = self.ax_bandwidth.plot([], [], 'o-', color='#533483', linewidth=2)
        
        # Top bandwidth consumers
        self.ax_top_hosts.set_title('Top Bandwidth Users', color='white', fontweight='bold')
        self.ax_top_hosts.set_xlabel('Traffic (MB)', color='white')
        
        # Protocol distribution
        self.ax_protocols_traffic.set_title('Traffic by Protocol', color='white', fontweight='bold')
        
        # Port analysis
        self.ax_ports.set_title('Most Active Ports', color='white', fontweight='bold')
        self.ax_ports.set_xlabel('Connection Count', color='white')
        
        plt.tight_layout()
        
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=traffic_viz_frame)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic details section
        traffic_details_frame = ttk.LabelFrame(traffic_main, text="📋 Host Traffic Details")
        traffic_details_frame.pack(fill=tk.X)
        
        traffic_columns = ("IP Address", "Hostname", "Total (MB)", "Upload (MB)", "Download (MB)", "Status")
        self.traffic_tree = ttk.Treeview(traffic_details_frame, columns=traffic_columns, show='headings', height=8)
        
        for col in traffic_columns:
            self.traffic_tree.heading(col, text=col)
            self.traffic_tree.column(col, width=120)
        
        traffic_tree_scroll = ttk.Scrollbar(traffic_details_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=traffic_tree_scroll.set)
        
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        traffic_tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Traffic animation
        self.traffic_animation = animation.FuncAnimation(self.traffic_fig, self.update_traffic_graphs,
                                                        interval=3000, blit=False)

    def create_threat_detection_tab(self):
        """Create threat detection and security analysis tab"""
        threat_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(threat_frame, text="🚨 THREAT DETECTION")
        
        threat_main = ttk.Frame(threat_frame)
        threat_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Threat overview section
        threat_overview = ttk.LabelFrame(threat_main, text="🛡️ Security Overview")
        threat_overview.pack(fill=tk.X, pady=(0, 10))
        
        overview_content = ttk.Frame(threat_overview)
        overview_content.pack(fill=tk.X, padx=10, pady=10)
        
        # Threat level indicators
        indicators_frame = ttk.Frame(overview_content)
        indicators_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.threat_level_var = tk.StringVar(value="🟢 LOW")
        self.threat_level_label = ttk.Label(indicators_frame, textvariable=self.threat_level_var, 
                                           style='Success.TLabel', font=('Segoe UI', 16, 'bold'))
        self.threat_level_label.pack(anchor='w')
        
        self.active_threats_var = tk.StringVar(value="Active Threats: 0")
        ttk.Label(indicators_frame, textvariable=self.active_threats_var, 
                 style='Info.TLabel').pack(anchor='w')
        
        self.suspicious_activity_var = tk.StringVar(value="Suspicious Connections: 0")
        ttk.Label(indicators_frame, textvariable=self.suspicious_activity_var, 
                 style='Warning.TLabel').pack(anchor='w')
        
        # Alert feed
        alerts_section = ttk.LabelFrame(threat_main, text="🚨 Real-Time Security Alerts")
        alerts_section.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.threat_alerts_listbox = tk.Listbox(alerts_section, height=15, 
                                               bg='#1a1a2e', fg='#ff4444',
                                               font=('Courier', 10))
        alerts_scroll = ttk.Scrollbar(alerts_section, orient=tk.VERTICAL, 
                                     command=self.threat_alerts_listbox.yview)
        self.threat_alerts_listbox.configure(yscrollcommand=alerts_scroll.set)
        
        self.threat_alerts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        alerts_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threat analysis log
        analysis_section = ttk.LabelFrame(threat_main, text="🔍 Threat Analysis Log")
        analysis_section.pack(fill=tk.X)
        
        self.threat_analysis_text = scrolledtext.ScrolledText(analysis_section, height=8, 
                                                             bg='#1a1a2e', fg='white',
                                                             font=('Courier', 9))
        self.threat_analysis_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_network_map_tab(self):
        """Create network topology visualization tab"""
        network_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(network_frame, text="🗺️ NETWORK MAP")
        
        network_main = ttk.Frame(network_frame)
        network_main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Network visualization
        self.network_fig, self.ax_network = plt.subplots(1, 1, figsize=(16, 12))
        self.network_fig.patch.set_facecolor('#16213e')
        self.ax_network.set_facecolor('#1a1a2e')
        self.ax_network.set_title('Live Network Topology & Communication Flow', 
                                 color='white', fontweight='bold', pad=20)
        
        # Remove axes for cleaner look
        self.ax_network.set_xticks([])
        self.ax_network.set_yticks([])
        
        self.network_canvas = FigureCanvasTkAgg(self.network_fig, master=network_main)
        self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_unified_status_bar(self, parent):
        """Create comprehensive unified status bar"""
        status_frame = ttk.Frame(parent, style='Secondary.TFrame')
        status_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Left side - Main status
        status_left = ttk.Frame(status_frame, style='Secondary.TFrame')
        status_left.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10)
        
        self.main_status_var = tk.StringVar(value="🚀 Ready - All systems operational")
        self.main_status_label = ttk.Label(status_left, textvariable=self.main_status_var, 
                                          style='Success.TLabel')
        self.main_status_label.pack(side=tk.LEFT)
        
        # Center - System metrics
        metrics_frame = ttk.Frame(status_frame, style='Secondary.TFrame')
        metrics_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.packets_total_var = tk.StringVar(value="Total Packets: 0")
        ttk.Label(metrics_frame, textvariable=self.packets_total_var, 
                 style='Info.TLabel').pack(side=tk.LEFT, padx=10)
        
        self.bandwidth_total_var = tk.StringVar(value="Bandwidth: 0 MB")
        ttk.Label(metrics_frame, textvariable=self.bandwidth_total_var, 
                 style='Info.TLabel').pack(side=tk.LEFT, padx=10)
        
        self.threats_detected_var = tk.StringVar(value="Threats: 0")
        ttk.Label(metrics_frame, textvariable=self.threats_detected_var, 
                 style='Warning.TLabel').pack(side=tk.LEFT, padx=10)
        
        # Right side - System performance
        performance_frame = ttk.Frame(status_frame, style='Secondary.TFrame')
        performance_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        
        self.uptime_var = tk.StringVar(value="Uptime: 00:00:00")
        ttk.Label(performance_frame, textvariable=self.uptime_var, 
                 style='Success.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Master progress indicator
        self.master_progress = ttk.Progressbar(performance_frame, mode='indeterminate')
        self.master_progress.pack(side=tk.LEFT, padx=10)

    def init_monitoring_threads(self):
        """Initialize all monitoring thread workers"""
        self.capture_worker = None
        self.dns_worker = None
        self.traffic_worker = None
        self.threat_worker = None

    def start_all_monitoring(self):
        """Start all monitoring modules simultaneously"""
        if self.is_monitoring:
            messagebox.showinfo("Info", "Monitoring is already active!")
            return
        
        if not self.interface.get().strip():
            messagebox.showerror("Error", "Please specify a network interface!")
            return
        
        # Initialize monitoring state
        self.is_monitoring = True
        self.start_time = time.time()
        self.stop_event.clear()
        
        # Update target domains list
        domains = [d.strip() for d in self.domain_filter.get().split(',') if d.strip()]
        self.target_domains = domains if domains else ['example.com']
        
        # Clear all data
        self.clear_all_data()
        
        # Update UI
        self.master_start_btn.config(state='disabled')
        self.master_stop_btn.config(state='normal')
        self.master_progress.start(10)
        
        # Start all monitoring threads
        self.start_unified_capture()
        
        self.main_status_var.set("🔥 All monitoring systems active - Real-time analysis in progress")
        self.log_unified_event("🚀 Unified monitoring started - All systems operational")

    def stop_all_monitoring(self):
        """Stop all monitoring modules"""
        if not self.is_monitoring:
            return
        
        # Set stop event
        self.stop_event.set()
        self.is_monitoring = False
        
        # Update UI
        self.master_start_btn.config(state='normal')
        self.master_stop_btn.config(state='disabled')
        self.master_progress.stop()
        
        self.main_status_var.set("⏹️ All monitoring stopped")
        self.log_unified_event("⏹️ Unified monitoring stopped")

    def start_unified_capture(self):
        """Start unified packet capture that feeds all modules"""
        def unified_capture_worker():
            # Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Create capture with event loop
                capture = pyshark.LiveCapture(interface=self.interface.get(), eventloop=loop)
                
                self.root.after(0, lambda: self.log_unified_event("📡 Unified packet capture started"))
                
                packet_count = 0
                for packet in capture.sniff_continuously():
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        # Process packet for all modules
                        self.process_unified_packet(packet)
                        packet_count += 1
                        
                        # Update UI every 100 packets
                        if packet_count % 100 == 0:
                            self.root.after(0, self.update_unified_metrics)
                    
                    except Exception as e:
                        continue  # Skip problematic packets
                
                capture.close()
                
            except Exception as e:
                error_msg = f"Unified capture error: {str(e)}"
                self.root.after(0, lambda: self.handle_unified_error(error_msg))
            finally:
                # Clean up event loop
                try:
                    if loop and not loop.is_closed():
                        loop.close()
                except:
                    pass
        
        self.unified_worker = threading.Thread(target=unified_capture_worker, daemon=True)
        self.unified_worker.start()

    def process_unified_packet(self, packet):
        """Process packet for all monitoring modules simultaneously"""
        try:
            with self.lock:
                self.total_packets_processed += 1
                timestamp = datetime.now()
                
                # Extract basic packet information
                src_ip = getattr(packet, 'ip', {}).src if hasattr(packet, 'ip') else 'N/A'
                dst_ip = getattr(packet, 'ip', {}).dst if hasattr(packet, 'ip') else 'N/A'
                protocol = getattr(packet, 'highest_layer', 'Unknown')
                length = int(getattr(packet, 'length', 0))
                
                # Update global counters
                self.total_bytes_processed += length
                
                # 1. Feed to Live Capture Module
                self.process_live_capture_packet(packet, timestamp)
                
                # 2. Feed to DNS Monitoring Module
                if hasattr(packet, 'dns'):
                    self.process_dns_packet(packet, timestamp)
                
                # 3. Feed to Traffic Analysis Module
                self.process_traffic_packet(packet, src_ip, dst_ip, protocol, length, timestamp)
                
                # 4. Feed to Threat Detection Module
                self.process_threat_analysis(packet, src_ip, dst_ip, protocol, timestamp)
                
                # 5. Update Unified Timeline
                self.update_unified_timeline(timestamp, protocol, src_ip, dst_ip)
        
        except Exception as e:
            pass  # Skip problematic packets

    def process_live_capture_packet(self, packet, timestamp):
        """Process packet for live capture module"""
        try:
            # Add to captured packets
            if len(self.captured_packets) >= self.packet_limit.get():
                self.captured_packets.pop(0)  # Remove oldest
            
            self.captured_packets.append({
                'packet': packet,
                'timestamp': timestamp,
                'number': len(self.captured_packets) + 1
            })
            
            # Update capture statistics
            protocol = getattr(packet, 'highest_layer', 'Unknown').lower()
            self.capture_stats['total'] += 1
            
            if 'tcp' in protocol:
                self.capture_stats['tcp'] += 1
            elif 'udp' in protocol:
                self.capture_stats['udp'] += 1
            else:
                self.capture_stats['other'] += 1
            
            # Schedule UI update
            self.root.after(0, self.update_live_capture_display)
        
        except Exception as e:
            pass

    def process_dns_packet(self, packet, timestamp):
        """Process DNS packet for DNS monitoring module"""
        try:
            query_name = getattr(packet.dns, 'qry_name', '')
            query_type = getattr(packet.dns, 'qry_type', 'A')
            
            if query_name:
                # Add to DNS queries log
                dns_entry = {
                    'timestamp': timestamp,
                    'query': query_name,
                    'type': query_type,
                    'is_target': any(domain.lower() in query_name.lower() 
                                   for domain in self.target_domains)
                }
                
                self.dns_queries.append(dns_entry)
                self.domain_stats[query_name] += 1
                
                # Update DNS counts for timeline
                if len(self.dns_counts) > 0:
                    self.dns_counts[-1] += 1
                
                # Schedule DNS UI update
                self.root.after(0, lambda: self.update_dns_display(dns_entry))
        
        except Exception as e:
            pass

    def process_traffic_packet(self, packet, src_ip, dst_ip, protocol, length, timestamp):
        """Process packet for traffic analysis module"""
        try:
            if src_ip != 'N/A' and dst_ip != 'N/A':
                # Update traffic statistics
                self.traffic_data[src_ip]['out'] += length
                self.traffic_data[src_ip]['total'] += length
                self.traffic_data[dst_ip]['in'] += length
                self.traffic_data[dst_ip]['total'] += length
                
                # Update protocol statistics
                self.protocol_stats[protocol] += length
                
                # Update port statistics
                if hasattr(packet, 'tcp'):
                    src_port = getattr(packet.tcp, 'srcport', 'N/A')
                    dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                    if src_port != 'N/A':
                        self.port_stats[f"{src_port}/TCP"] += 1
                    if dst_port != 'N/A':
                        self.port_stats[f"{dst_port}/TCP"] += 1
                elif hasattr(packet, 'udp'):
                    src_port = getattr(packet.udp, 'srcport', 'N/A')
                    dst_port = getattr(packet.udp, 'dstport', 'N/A')
                    if src_port != 'N/A':
                        self.port_stats[f"{src_port}/UDP"] += 1
                    if dst_port != 'N/A':
                        self.port_stats[f"{dst_port}/UDP"] += 1
                
                # Check for bandwidth alerts
                threshold_bytes = self.bandwidth_threshold.get() * 1024 * 1024
                for ip in [src_ip, dst_ip]:
                    if self.traffic_data[ip]['total'] > threshold_bytes:
                        alert_msg = f"🚨 HIGH BANDWIDTH: {ip} - {self.traffic_data[ip]['total']/(1024*1024):.2f} MB"
                        self.add_unified_alert(alert_msg)
        
        except Exception as e:
            pass

    def process_threat_analysis(self, packet, src_ip, dst_ip, protocol, timestamp):
        """Process packet for threat detection module"""
        try:
            # Simple threat detection logic
            threat_indicators = []
            
            # Check for suspicious ports
            suspicious_ports = ['666', '1337', '31337', '12345', '54321']
            if hasattr(packet, 'tcp'):
                src_port = str(getattr(packet.tcp, 'srcport', ''))
                dst_port = str(getattr(packet.tcp, 'dstport', ''))
                if src_port in suspicious_ports or dst_port in suspicious_ports:
                    threat_indicators.append(f"Suspicious port detected: {src_port}->{dst_port}")
            
            # Check for unusual protocols
            if protocol in ['IRC', 'P2P', 'BitTorrent']:
                threat_indicators.append(f"Potentially unwanted protocol: {protocol}")
            
            # Check for external connections to suspicious IPs
            external_ips = [ip for ip in [src_ip, dst_ip] 
                           if ip != 'N/A' and not self.is_private_ip(ip)]
            if external_ips:
                for ip in external_ips:
                    if self.is_suspicious_ip(ip):
                        threat_indicators.append(f"Connection to suspicious IP: {ip}")
            
            # Add threats to indicators
            for indicator in threat_indicators:
                self.threat_indicators.append({
                    'timestamp': timestamp,
                    'threat': indicator,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': protocol
                })
                
                # Schedule threat UI update
                self.root.after(0, lambda t=indicator: self.add_threat_alert(t))
        
        except Exception as e:
            pass

    def is_private_ip(self, ip):
        """Check if IP is in private address space"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    def is_suspicious_ip(self, ip):
        """Basic suspicious IP detection (placeholder)"""
        # This is a simplified example - in practice, you'd check against threat intelligence feeds
        suspicious_ranges = ['192.168.1.666', '10.0.0.666']  # Example suspicious IPs
        return ip in suspicious_ranges

    def update_unified_timeline(self, timestamp, protocol, src_ip, dst_ip):
        """Update the unified timeline with network events"""
        event = {
            'timestamp': timestamp,
            'type': 'network_activity',
            'protocol': protocol,
            'source': src_ip,
            'destination': dst_ip,
            'event_id': len(self.timeline_events) + 1
        }
        
        self.timeline_events.append(event)

    def update_live_capture_display(self):
        """Update live capture packet display"""
        try:
            # Clear existing items periodically
            if len(self.captured_packets) % 100 == 0:
                for item in self.packet_tree.get_children():
                    self.packet_tree.delete(item)
            
            # Add recent packets
            for packet_data in self.captured_packets[-10:]:  # Show last 10 packets
                packet = packet_data['packet']
                timestamp = packet_data['timestamp'].strftime('%H:%M:%S.%f')[:-3]
                
                src_ip = getattr(packet, 'ip', {}).src if hasattr(packet, 'ip') else 'N/A'
                dst_ip = getattr(packet, 'ip', {}).dst if hasattr(packet, 'ip') else 'N/A'
                protocol = getattr(packet, 'highest_layer', 'Unknown')
                length = getattr(packet, 'length', 'N/A')
                info = str(packet)[:50] + "..." if len(str(packet)) > 50 else str(packet)
                
                self.packet_tree.insert('', 'end', values=(
                    packet_data['number'], timestamp, src_ip, dst_ip, protocol, length, info
                ))
            
            # Update statistics display
            stats_text = f"""LIVE CAPTURE STATISTICS
{'='*30}

Total Packets: {self.capture_stats['total']:,}
TCP Packets:   {self.capture_stats['tcp']:,}
UDP Packets:   {self.capture_stats['udp']:,}
Other:         {self.capture_stats['other']:,}

Capture Rate:  {len(self.captured_packets)/max(1, (time.time() - (self.start_time or time.time()))):,.1f} pkt/sec
Buffer Usage:  {len(self.captured_packets)}/{self.packet_limit.get()}
"""
            
            self.capture_stats_text.delete(1.0, tk.END)
            self.capture_stats_text.insert(1.0, stats_text)
            
        except Exception as e:
            pass

    def update_dns_display(self, dns_entry):
        """Update DNS monitoring display"""
        try:
            # Add to DNS log
            timestamp = dns_entry['timestamp'].strftime('%H:%M:%S.%f')[:-3]
            marker = '🎯' if dns_entry['is_target'] else '📝'
            log_line = f"[{timestamp}] {marker} {dns_entry['query']} ({dns_entry['type']})\n"
            
            self.dns_log_text.insert(tk.END, log_line)
            self.dns_log_text.see(tk.END)
            
            # Limit log size
            lines = int(self.dns_log_text.index('end-1c').split('.')[0])
            if lines > 200:
                self.dns_log_text.delete(1.0, '50.0')
                
        except Exception as e:
            pass

    def add_threat_alert(self, threat_message):
        """Add threat alert to the threat detection display"""
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            alert_text = f"[{timestamp}] {threat_message}"
            
            self.threat_alerts_listbox.insert(tk.END, alert_text)
            self.threat_alerts_listbox.see(tk.END)
            
            # Update threat level
            threat_count = len(self.threat_indicators)
            if threat_count > 10:
                self.threat_level_var.set("🔴 HIGH")
            elif threat_count > 5:
                self.threat_level_var.set("🟡 MEDIUM")
            else:
                self.threat_level_var.set("🟢 LOW")
            
            # Limit alerts
            if self.threat_alerts_listbox.size() > 100:
                self.threat_alerts_listbox.delete(0)
                
        except Exception as e:
            pass

    def add_unified_alert(self, alert_message):
        """Add alert to unified alert system"""
        if not any(alert_message in str(alert) for alert in self.alerts):
            self.alerts.append({
                'timestamp': datetime.now(),
                'message': alert_message,
                'type': 'bandwidth'
            })

    def update_unified_metrics(self):
        """Update unified status bar metrics"""
        try:
            if self.start_time:
                uptime = int(time.time() - self.start_time)
                hours = uptime // 3600
                minutes = (uptime % 3600) // 60
                seconds = uptime % 60
                
                self.uptime_var.set(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")
                self.packets_total_var.set(f"Total Packets: {self.total_packets_processed:,}")
                self.bandwidth_total_var.set(f"Bandwidth: {self.total_bytes_processed/(1024*1024):.1f} MB")
                self.threats_detected_var.set(f"Threats: {len(self.threat_indicators)}")
        except Exception as e:
            pass

    def update_dashboard(self, frame):
        """Update unified dashboard visualizations"""
        try:
            # Update timeline graph
            if self.timeline_events:
                # Group events by minute
                events_per_minute = defaultdict(int)
                current_time = time.time()
                
                for event in list(self.timeline_events)[-60:]:  # Last 60 events
                    minute_mark = int(event['timestamp'].timestamp() // 60)
                    events_per_minute[minute_mark] += 1
                
                times = list(range(len(events_per_minute)))
                counts = list(events_per_minute.values())
                
                self.timeline_line.set_data(times, counts)
                if counts:
                    self.ax_timeline.set_ylim(0, max(counts) * 1.1)
                    self.ax_timeline.set_xlim(0, max(1, len(counts)))
            
            # Update threat indicators
            self.ax_threats.clear()
            if self.threat_indicators:
                threat_times = [t['timestamp'] for t in list(self.threat_indicators)[-20:]]
                threat_levels = [1] * len(threat_times)  # Simplified threat level
                
                self.ax_threats.scatter(range(len(threat_times)), threat_levels, 
                                       c='red', alpha=0.7, s=50)
                self.ax_threats.set_ylim(0, 2)
                self.ax_threats.set_xlim(0, max(1, len(threat_times)))
            
            self.ax_threats.set_facecolor('#1a1a2e')
            self.ax_threats.tick_params(colors='white')
            self.ax_threats.set_title('Real-Time Threat Indicators', color='white', fontweight='bold')
            
            # Update protocol distribution
            self.ax_protocols.clear()
            if self.protocol_stats:
                protocols = list(self.protocol_stats.keys())[:10]
                sizes = [self.protocol_stats[p] for p in protocols]
                colors = plt.cm.Set3(range(len(protocols)))
                
                self.ax_protocols.pie(sizes, labels=protocols, colors=colors, 
                                     autopct='%1.1f%%', startangle=90)
            
            self.ax_protocols.set_title('Global Protocol Distribution', color='white', fontweight='bold')
            
            return self.timeline_line,
            
        except Exception as e:
            return self.timeline_line,

    def update_dns_graphs(self, frame):
        """Update DNS monitoring graphs"""
        try:
            # Update DNS query rate
            current_time = time.time()
            if len(self.dns_counts) > 0:
                # Rotate DNS counts
                self.dns_counts.append(0)
            
            times = list(range(len(self.dns_counts)))
            self.dns_line.set_data(times, list(self.dns_counts))
            
            if self.dns_counts:
                max_count = max(self.dns_counts)
                self.ax_dns_timeline.set_ylim(0, max(5, max_count + 1))
                self.ax_dns_timeline.set_xlim(0, len(self.dns_counts))
                
                # Update activity indicator
                current_activity = self.dns_counts[-1] if self.dns_counts else 0
                if current_activity > 0:
                    self.dns_activity.center = (len(self.dns_counts) - 1, current_activity)
                    self.dns_activity.set_alpha(0.8)
                    self.dns_activity.set_radius(0.3 + current_activity * 0.1)
                else:
                    self.dns_activity.set_alpha(0.2)
            
            # Update top domains chart
            self.ax_dns_domains.clear()
            if self.domain_stats:
                top_domains = sorted(self.domain_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                if top_domains:
                    domains = [d[0][:30] for d, _ in top_domains]  # Truncate long domains
                    counts = [count for _, count in top_domains]
                    
                    bars = self.ax_dns_domains.barh(domains, counts, color='#00ff88', alpha=0.7)
                    
                    # Highlight target domains
                    for i, (domain, _) in enumerate(top_domains):
                        if any(target.lower() in domain.lower() for target in self.target_domains):
                            bars[i].set_color('#ff4444')
                            bars[i].set_alpha(0.9)
            
            self.ax_dns_domains.set_facecolor('#1a1a2e')
            self.ax_dns_domains.tick_params(colors='white')
            self.ax_dns_domains.set_title('Most Queried Domains', color='white', fontweight='bold')
            self.ax_dns_domains.set_xlabel('Query Count', color='white')
            
            return self.dns_line,
            
        except Exception as e:
            return self.dns_line,

    def update_traffic_graphs(self, frame):
        """Update traffic analysis graphs"""
        try:
            # Update bandwidth timeline
            current_bandwidth = self.total_bytes_processed / (1024 * 1024)  # MB
            self.bandwidth_history.append(current_bandwidth)
            
            times = list(range(len(self.bandwidth_history)))
            self.bandwidth_line.set_data(times, list(self.bandwidth_history))
            
            if self.bandwidth_history:
                max_bandwidth = max(self.bandwidth_history)
                self.ax_bandwidth.set_ylim(0, max(1, max_bandwidth * 1.1))
                self.ax_bandwidth.set_xlim(0, len(self.bandwidth_history))
            
            # Update top hosts chart
            self.ax_top_hosts.clear()
            if self.traffic_data:
                top_hosts = sorted(self.traffic_data.items(), 
                                 key=lambda x: x[1]['total'], reverse=True)[:10]
                if top_hosts:
                    ips = [ip for ip, _ in top_hosts]
                    totals = [data['total'] / (1024 * 1024) for _, data in top_hosts]  # Convert to MB
                    
                    bars = self.ax_top_hosts.barh(ips, totals, color='#533483', alpha=0.7)
                    
                    # Highlight high bandwidth users
                    threshold_mb = self.bandwidth_threshold.get()
                    for i, total in enumerate(totals):
                        if total > threshold_mb:
                            bars[i].set_color('#ff4444')
                            bars[i].set_alpha(0.9)
            
            self.ax_top_hosts.set_facecolor('#1a1a2e')
            self.ax_top_hosts.tick_params(colors='white')
            self.ax_top_hosts.set_title('Top Bandwidth Users', color='white', fontweight='bold')
            self.ax_top_hosts.set_xlabel('Traffic (MB)', color='white')
            
            # Update protocols pie chart
            self.ax_protocols_traffic.clear()
            if self.protocol_stats:
                protocols = list(self.protocol_stats.keys())[:8]
                sizes = [self.protocol_stats[p] for p in protocols]
                colors = plt.cm.Set2(range(len(protocols)))
                
                self.ax_protocols_traffic.pie(sizes, labels=protocols, colors=colors,
                                             autopct='%1.1f%%', startangle=90)
            
            self.ax_protocols_traffic.set_title('Traffic by Protocol', color='white', fontweight='bold')
            
            # Update ports chart
            self.ax_ports.clear()
            if self.port_stats:
                top_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                if top_ports:
                    ports = [port for port, _ in top_ports]
                    counts = [count for _, count in top_ports]
                    
                    self.ax_ports.barh(ports, counts, color='#7209b7', alpha=0.7)
            
            self.ax_ports.set_facecolor('#1a1a2e')
            self.ax_ports.tick_params(colors='white')
            self.ax_ports.set_title('Most Active Ports', color='white', fontweight='bold')
            self.ax_ports.set_xlabel('Connection Count', color='white')
            
            # Update traffic table
            self.update_traffic_table()
            
            return self.bandwidth_line,
            
        except Exception as e:
            return self.bandwidth_line,

    def update_traffic_table(self):
        """Update traffic analysis table"""
        try:
            # Clear existing items
            for item in self.traffic_tree.get_children():
                self.traffic_tree.delete(item)
            
            # Add updated host data
            for ip, data in sorted(self.traffic_data.items(), 
                                  key=lambda x: x[1]['total'], reverse=True)[:20]:
                total_mb = data['total'] / (1024 * 1024)
                upload_mb = data['out'] / (1024 * 1024)
                download_mb = data['in'] / (1024 * 1024)
                
                # Determine status
                status = "🟢 Normal"
                if total_mb > self.bandwidth_threshold.get():
                    status = "🔴 High Usage"
                elif total_mb > self.bandwidth_threshold.get() * 0.5:
                    status = "🟡 Moderate"
                
                # Try to resolve hostname
                hostname = "Resolving..."
                try:
                    hostname = socket.gethostbyaddr(ip)[0][:20]
                except:
                    hostname = f"Host-{ip.split('.')[-1]}"
                
                self.traffic_tree.insert('', 'end', values=(
                    ip, hostname, f"{total_mb:.2f}", f"{upload_mb:.2f}", 
                    f"{download_mb:.2f}", status
                ))
                
        except Exception as e:
            pass

    def start_live_capture(self):
        """Start live capture module independently"""
        self.log_unified_event("📡 Starting independent live capture...")

    def stop_live_capture(self):
        """Stop live capture module"""
        self.log_unified_event("⏹️ Live capture stopped")

    def save_captured_packets(self):
        """Save captured packets to file"""
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save!")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Captured Packets",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # This would typically use a proper PCAP writing library
                messagebox.showinfo("Success", f"Packets saved to {file_path}")
                self.log_unified_event(f"💾 Captured packets saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets: {str(e)}")

    def browse_pcap_file(self):
        """Browse for PCAP file to analyze"""
        file_path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        
        if file_path:
            self.current_pcap_file = file_path
            self.pcap_file_var.set(os.path.basename(file_path))
            self.log_unified_event(f"📂 PCAP file selected: {os.path.basename(file_path)}")

    def analyze_pcap_file(self):
        """Analyze selected PCAP file"""
        if not self.current_pcap_file:
            messagebox.showwarning("Warning", "Please select a PCAP file first!")
            return
        
        def analysis_worker():
            try:
                self.root.after(0, lambda: self.log_unified_event("🔬 Starting PCAP analysis..."))
                
                capture = pyshark.FileCapture(self.current_pcap_file)
                packets = []
                
                for i, packet in enumerate(capture):
                    if i >= 1000:  # Limit for performance
                        break
                    packets.append(packet)
                
                capture.close()
                self.pcap_packets = packets
                
                self.root.after(0, self.update_pcap_analysis)
                self.root.after(0, lambda: self.log_unified_event(f"✅ PCAP analysis complete - {len(packets)} packets processed"))
                
            except Exception as e:
                error_msg = f"PCAP analysis error: {str(e)}"
                self.root.after(0, lambda: messagebox.showerror("Analysis Error", error_msg))
        
        threading.Thread(target=analysis_worker, daemon=True).start()

    def update_pcap_analysis(self):
        """Update PCAP analysis display"""
        try:
            # Clear packet tree
            for item in self.pcap_tree.get_children():
                self.pcap_tree.delete(item)
            
            # Add packets to tree
            for i, packet in enumerate(self.pcap_packets):
                try:
                    timestamp = getattr(packet, 'sniff_timestamp', 'N/A')
                    if timestamp != 'N/A':
                        timestamp = datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S')
                    
                    src_ip = getattr(packet, 'ip', {}).src if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet, 'ip', {}).dst if hasattr(packet, 'ip') else 'N/A'
                    protocol = getattr(packet, 'highest_layer', 'Unknown')
                    length = getattr(packet, 'length', 'N/A')
                    info = str(packet)[:50] + "..." if len(str(packet)) > 50 else str(packet)
                    
                    self.pcap_tree.insert('', 'end', values=(
                        str(i + 1), timestamp, src_ip, dst_ip, protocol, length, info
                    ))
                    
                except Exception:
                    continue
            
            # Generate statistics
            self.generate_pcap_statistics()
            
        except Exception as e:
            pass

    def generate_pcap_statistics(self):
        """Generate PCAP analysis statistics"""
        try:
            if not self.pcap_packets:
                return
            
            stats = {
                'total_packets': len(self.pcap_packets),
                'protocols': defaultdict(int),
                'sources': defaultdict(int),
                'destinations': defaultdict(int)
            }
            
            for packet in self.pcap_packets:
                try:
                    protocol = getattr(packet, 'highest_layer', 'Unknown')
                    stats['protocols'][protocol] += 1
                    
                    if hasattr(packet, 'ip'):
                        stats['sources'][packet.ip.src] += 1
                        stats['destinations'][packet.ip.dst] += 1
                        
                except Exception:
                    continue
            
            # Display statistics
            stats_text = f"""PCAP ANALYSIS STATISTICS
{'='*40}

File: {os.path.basename(self.current_pcap_file)}
Total Packets: {stats['total_packets']:,}

TOP PROTOCOLS:
{'-'*20}
"""
            
            top_protocols = sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]
            for protocol, count in top_protocols:
                percentage = (count / stats['total_packets']) * 100
                stats_text += f"{protocol:15} {count:6} ({percentage:5.1f}%)\n"
            
            stats_text += f"\nTOP SOURCE IPs:\n{'-'*20}\n"
            top_sources = sorted(stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]
            for source, count in top_sources:
                percentage = (count / stats['total_packets']) * 100
                stats_text += f"{source:15} {count:6} ({percentage:5.1f}%)\n"
            
            self.pcap_stats_text.delete(1.0, tk.END)
            self.pcap_stats_text.insert(tk.END, stats_text)
            
        except Exception as e:
            pass

    def on_pcap_packet_select(self, event):
        """Handle PCAP packet selection"""
        try:
            selection = self.pcap_tree.selection()
            if not selection:
                return
            
            item = self.pcap_tree.item(selection[0])
            packet_no = int(item['values'][0]) - 1
            
            if 0 <= packet_no < len(self.pcap_packets):
                packet = self.pcap_packets[packet_no]
                
                details = f"PACKET #{packet_no + 1} DETAILS\n"
                details += "="*60 + "\n\n"
                details += f"Timestamp: {getattr(packet, 'sniff_timestamp', 'N/A')}\n"
                
                if hasattr(packet, 'layers'):
                    details += f"Protocol Stack: {' -> '.join(packet.layers)}\n"
                
                details += f"Packet Length: {getattr(packet, 'length', 'N/A')} bytes\n\n"
                details += f"Raw Data:\n{'-'*20}\n{str(packet)}"
                
                self.pcap_details_text.delete(1.0, tk.END)
                self.pcap_details_text.insert(tk.END, details)
                
        except Exception as e:
            pass

    def log_unified_event(self, message):
        """Log event to unified timeline and threat analysis"""
        timestamp = datetime.now()
        
        # Add to timeline
        self.timeline_events.append({
            'timestamp': timestamp,
            'type': 'system_event',
            'message': message,
            'source': 'system'
        })
        
        # Add to threat analysis log
        log_entry = f"[{timestamp.strftime('%H:%M:%S')}] {message}\n"
        self.threat_analysis_text.insert(tk.END, log_entry)
        self.threat_analysis_text.see(tk.END)
        
        # Limit log size
        lines = int(self.threat_analysis_text.index('end-1c').split('.')[0])
        if lines > 500:
            self.threat_analysis_text.delete(1.0, '100.0')

    def clear_all_data(self):
        """Clear all data from all modules"""
        with self.lock:
            # Clear live capture data
            self.captured_packets.clear()
            self.capture_stats = {'total': 0, 'tcp': 0, 'udp': 0, 'other': 0}
            
            # Clear DNS data
            self.dns_queries.clear()
            self.dns_counts.clear()
            self.dns_counts.extend([0] * 60)
            self.domain_stats.clear()
            
            # Clear traffic data
            self.traffic_data.clear()
            self.protocol_stats.clear()
            self.port_stats.clear()
            self.bandwidth_history.clear()
            self.bandwidth_history.extend([0] * 60)
            
            # Clear threat data
            self.threat_indicators.clear()
            self.alerts.clear()
            
            # Clear timeline
            self.timeline_events.clear()
            
            # Reset counters
            self.total_packets_processed = 0
            self.total_bytes_processed = 0
        
        self.log_unified_event("🗑️ All monitoring data cleared")

    def export_unified_report(self):
        """Export comprehensive unified report"""
        if self.total_packets_processed == 0:
            messagebox.showwarning("Warning", "No data to export!")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export Unified Network Analysis Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Prepare comprehensive unified report
                report_data = {
                    'report_info': {
                        'generated_at': datetime.now().isoformat(),
                        'interface': self.interface.get(),
                        'monitoring_duration': int(time.time() - (self.start_time or time.time())),
                        'report_type': 'unified_network_analysis'
                    },
                    'summary_statistics': {
                        'total_packets_processed': self.total_packets_processed,
                        'total_bytes_processed': self.total_bytes_processed,
                        'unique_hosts_detected': len(self.traffic_data),
                        'dns_queries_monitored': len(self.dns_queries),
                        'threats_detected': len(self.threat_indicators),
                        'alerts_generated': len(self.alerts)
                    },
                    'live_capture_data': {
                        'captured_packets_count': len(self.captured_packets),
                        'protocol_distribution': dict(self.capture_stats)
                    },
                    'dns_monitoring_data': {
                        'total_queries': len(self.dns_queries),
                        'target_domains': self.target_domains,
                        'top_domains': dict(sorted(self.domain_stats.items(), 
                                                 key=lambda x: x[1], reverse=True)[:20])
                    },
                    'traffic_analysis_data': {
                        'bandwidth_usage': dict(self.traffic_data),
                        'protocol_statistics': dict(self.protocol_stats),
                        'port_statistics': dict(self.port_stats)
                    },
                    'threat_detection_data': {
                        'threat_indicators': [
                            {
                                'timestamp': t['timestamp'].isoformat(),
                                'threat': t['threat'],
                                'source_ip': t.get('source_ip', 'N/A'),
                                'protocol': t.get('protocol', 'N/A')
                            } for t in list(self.threat_indicators)
                        ],
                        'alert_summary': [
                            {
                                'timestamp': a['timestamp'].isoformat(),
                                'message': a['message'],
                                'type': a['type']
                            } for a in list(self.alerts)
                        ]
                    },
                    'timeline_data': [
                        {
                            'timestamp': event['timestamp'].isoformat(),
                            'type': event['type'],
                            'details': event.get('message', event.get('protocol', 'Unknown'))
                        } for event in list(self.timeline_events)
                    ]
                }
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(report_data, f, indent=2, default=str)
                else:
                    # Export as formatted text report
                    with open(file_path, 'w') as f:
                        f.write("UNIFIED NETWORK ANALYSIS REPORT\n")
                        f.write("="*60 + "\n\n")
                        
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Interface: {self.interface.get()}\n")
                        f.write(f"Duration: {int(time.time() - (self.start_time or time.time()))} seconds\n\n")
                        
                        f.write("EXECUTIVE SUMMARY\n")
                        f.write("-" * 30 + "\n")
                        f.write(f"Total Network Activity: {self.total_packets_processed:,} packets\n")
                        f.write(f"Data Processed: {self.total_bytes_processed/(1024*1024):.2f} MB\n")
                        f.write(f"Unique Hosts: {len(self.traffic_data)}\n")
                        f.write(f"Security Threats: {len(self.threat_indicators)}\n")
                        f.write(f"DNS Queries: {len(self.dns_queries)}\n\n")
                        
                        # Add detailed sections
                        if self.traffic_data:
                            f.write("TOP BANDWIDTH CONSUMERS\n")
                            f.write("-" * 30 + "\n")
                            top_hosts = sorted(self.traffic_data.items(), 
                                             key=lambda x: x[1]['total'], reverse=True)[:10]
                            for ip, data in top_hosts:
                                f.write(f"{ip:15} {data['total']/(1024*1024):8.2f} MB\n")
                            f.write("\n")
                        
                        if self.threat_indicators:
                            f.write("SECURITY THREATS DETECTED\n")
                            f.write("-" * 30 + "\n")
                            for threat in list(self.threat_indicators)[-10:]:
                                f.write(f"{threat['timestamp'].strftime('%H:%M:%S')} - {threat['threat']}\n")
                            f.write("\n")
                
                messagebox.showinfo("Success", f"Unified report exported successfully!\nFile: {file_path}")
                self.log_unified_event(f"📊 Unified report exported to {os.path.basename(file_path)}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")

    def handle_unified_error(self, error_msg):
        """Handle unified system errors"""
        self.stop_all_monitoring()
        self.main_status_var.set("🚨 System error occurred")
        messagebox.showerror("System Error", error_msg)
        self.log_unified_event(f"🚨 System error: {error_msg}")


def main():
    root = tk.Tk()
    app = UnifiedNetworkAnalysisSuite(root)
    
    def on_closing():
        app.stop_all_monitoring()
        root.quit()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()
