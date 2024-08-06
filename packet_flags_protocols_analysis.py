import matplotlib.pyplot as plt
from scapy.all import *
from collections import Counter

# Function to capture packets and analyze data
def capture_and_analyze_packets(interface, capture_count):
    packets = sniff(iface=interface, count=capture_count)

    packet_count = len(packets)

    packet_sizes = [len(packet) for packet in packets]

    protocols = [packet.summary().split()[1] for packet in packets]

    ip_pairs = [(packet[IP].src, packet[IP].dst) for packet in packets if IP in packet]

    src_ports = [packet.sport for packet in packets if TCP in packet]
    dst_ports = [packet.dport for packet in packets if TCP in packet]
    ports = src_ports + dst_ports

    tcp_flags = [packet.sprintf('%TCP.flags%') for packet in packets if TCP in packet]

    return packet_count, packet_sizes, protocols, ip_pairs, ports, tcp_flags

# Function to generate and display a bar chart
def generate_bar_chart(data, title, x_label, y_label, x_ticks=None):
    plt.bar(range(len(data)), data)
    if x_ticks:
        plt.xticks(range(len(data)), x_ticks, rotation=45, ha="right")
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.tight_layout()
    plt.show()

# Function to generate and display a line chart
def generate_line_chart(x_data, y_data, title, x_label, y_label):
    plt.plot(x_data, y_data, marker='o')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid(True)
    plt.show()

# Function to generate and display a scatter chart
def generate_scatter_chart(x_data, y_data, title, x_label, y_label):
    plt.scatter(x_data, y_data, marker='o')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid(True)
    plt.show()

# Specify the interface to capture on and the number of packets to capture
interface = "Wi-Fi"
capture_count = 50

while True:
    # Capture and analyze packets
    packet_count, packet_sizes, protocols, ip_pairs, ports, tcp_flags = capture_and_analyze_packets(interface, capture_count)
    
    # Get user input for the selected graph
    print("Select a graph to generate:")
    print("1. Packet Count vs. Time")
    print("2. Packet Size Distribution")
    print("3. Protocol Distribution")
    print("4. Source/Destination IP Pair Distribution")
    print("5. Port Distribution")
    print("6. Flags Distribution")
    print("7. Quit")
    user_choice = input("Enter your choice (1-7): ")

    if user_choice == '7':
        break

    user_choice = int(user_choice)

    # Generate and display bar, line, and scatter charts for the selected graph based on the user's choice
    if user_choice == 1:
        # Packet Count vs. Time
        generate_bar_chart(packet_sizes, 'Packet Count vs. Time (Bar Chart)', 'Packet Count', 'Time')
        generate_line_chart(range(packet_count), packet_sizes, 'Packet Count vs. Time (Line Chart)', 'Packet Count', 'Time')
        generate_scatter_chart(range(packet_count), packet_sizes, 'Packet Count vs. Time (Scatter Chart)', 'Packet Count', 'Time')
    elif user_choice == 2:
        # Packet Size Distribution
        generate_bar_chart(packet_sizes, 'Packet Size Distribution (Bar Chart)', 'Packet Size', 'Frequency')
        generate_line_chart(range(len(packet_sizes)), packet_sizes, 'Packet Size Distribution (Line Chart)', 'Packet Index', 'Packet Size')
        generate_scatter_chart(range(len(packet_sizes)), packet_sizes, 'Packet Size Distribution (Scatter Chart)', 'Packet Index', 'Packet Size')
    elif user_choice == 3:
        # Protocol Distribution
        protocol_counts = Counter(protocols)
        labels = protocol_counts.keys()
        counts = protocol_counts.values()
        generate_bar_chart(counts, 'Protocol Distribution (Bar Chart)', 'Protocol', 'Percentage')
        generate_line_chart(range(len(counts)), counts, 'Protocol Distribution (Line Chart)', 'Protocol Index', 'Percentage')
        generate_scatter_chart(range(len(counts)), counts, 'Protocol Distribution (Scatter Chart)', 'Protocol Index', 'Percentage')
    elif user_choice == 4:
        # Source/Destination IP Pair Distribution
        top_ip_pairs = Counter(ip_pairs).most_common(5)
        ip_pair_labels = [f"{pair[0]} -> {pair[1]}" for pair, count in top_ip_pairs]
        ip_pair_counts = [count for pair, count in top_ip_pairs]
        generate_bar_chart(ip_pair_counts, 'Source/Destination IP Pair Distribution (Bar Chart)', 'IP Pairs', 'Packet Count', ip_pair_labels)
        generate_line_chart(range(len(ip_pair_counts)), ip_pair_counts, 'Source/Destination IP Pair Distribution (Line Chart)', 'Pair Index', 'Packet Count')
        generate_scatter_chart(range(len(ip_pair_counts)), ip_pair_counts, 'Source/Destination IP Pair Distribution (Scatter Chart)', 'Pair Index', 'Packet Count')
    elif user_choice == 5:
        # Port Distribution
        top_ports = Counter(ports).most_common(5)
        port_labels = [str(port[0]) for port in top_ports]
        port_counts = [port[1] for port in top_ports]
        generate_bar_chart(port_counts, 'Port Distribution (Bar Chart)', 'Ports', 'Packet Count', port_labels)
        generate_line_chart(range(len(port_counts)), port_counts, 'Port Distribution (Line Chart)', 'Port Index', 'Packet Count')
        generate_scatter_chart(range(len(port_counts)), port_counts, 'Port Distribution (Scatter Chart)', 'Port Index', 'Packet Count')
    elif user_choice == 6:
        # Flags Distribution
        flag_counts = Counter(tcp_flags)
        labels = flag_counts.keys()
        counts = flag_counts.values()
        generate_bar_chart(counts, 'Flags Distribution (Bar Chart)', 'Flags', 'Percentage')
        generate_line_chart(range(len(counts)), counts, 'Flags Distribution (Line Chart)', 'Flag Index', 'Percentage')
        generate_scatter_chart(range(len(counts)), counts, 'Flags Distribution (Scatter Chart)', 'Flag Index', 'Percentage')
    else:
        print("Invalid choice. Please select a valid option (1-6).")