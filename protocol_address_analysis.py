from scapy.all import *
import matplotlib.pyplot as plt
import plotly.express as px
from collections import defaultdict
from enum import Enum

# Enum for address types
class AddressType(Enum):
    IP = 'ip'
    MAC = 'mac'

# Enum for graph types
class GraphType(Enum):
    SCATTER = 'scatter'
    PIE = 'pie'
    LINE = 'line'
    BAR = 'bar'
    TREEMAP = 'treemap'
    QUIT = 'quit'

# Sniff packets and analyze them based on the selected protocol and address type
def analyze_packets(protocol, address_type):
    captured_packets = []  # List to store packet information

    def packet_handler(packet):
        if address_type == AddressType.IP.value and IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            captured_packets.append((src_ip, dst_ip))
        elif address_type == AddressType.MAC.value and Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            captured_packets.append((src_mac, dst_mac))

    # Start capturing packets with the specified protocol filter
    if address_type == AddressType.IP.value:
        filter_expr = f"{protocol}"
    else:
        filter_expr = ""

    # Sniff packets
    sniff(count=100, prn=packet_handler, filter=filter_expr)

    # Process captured packet data
    communication_counts = defaultdict(int)
    for src, dst in captured_packets:
        communication_counts[(src, dst)] += 1

    return communication_counts

def analyze_packets_mac():
    captured_packets = []  # List to store packet information

    def packet_handler_mac(packet):
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            captured_packets.append((src_mac, dst_mac))

    # Start capturing packets
    sniff(count=500, prn=packet_handler_mac)

    # Process captured packet data for MAC addresses
    mac_counts = defaultdict(int)
    for src, dst in captured_packets:
        mac_counts[(src, dst)] += 1

    return mac_counts

# Create different types of graphs based on user input
def create_graph_subplot(communication_counts1, communication_counts2, protocol, graph_type):
    communication_pairs1 = list(communication_counts1.keys())
    counts1 = list(communication_counts1.values())
    communication_pairs2 = list(communication_counts2.keys())
    counts2 = list(communication_counts2.values())

    if graph_type == GraphType.SCATTER.value:
        create_scatter_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol)
    elif graph_type == GraphType.PIE.value:
        create_pie_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol)
    elif graph_type == GraphType.LINE.value:
        create_line_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol)
    elif graph_type == GraphType.BAR.value:
        create_bar_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol)
    elif graph_type == GraphType.TREEMAP.value:
        create_treemap_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol)
    elif graph_type == GraphType.QUIT.value:
        sys.exit(0)
    else:
        print("Invalid graph type. Please select a valid graph type (scatter/pie/line/bar/treemap/quit).")

# Create a scatter plot subplot
def create_scatter_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol):
    plt.figure(figsize=(12, 6))
    plt.subplot(121)
    plt.scatter(range(len(communication_pairs1)), counts1)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Scatter Plot for Protocol: {protocol} (Normal)')
    plt.xticks(range(len(communication_pairs1)), communication_pairs1, rotation='vertical')
    plt.tight_layout()
    
    plt.subplot(122)
    plt.scatter(range(len(communication_pairs2)), counts2)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Scatter Plot for Protocol: {protocol} (Abnormal)')
    plt.xticks(range(len(communication_pairs2)), communication_pairs2, rotation='vertical')
    plt.tight_layout()
    
    plt.show()

# Create a pie chart subplot
def create_pie_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol):
    plt.figure(figsize=(12, 6))
    plt.subplot(121)
    plt.pie(counts1, labels=communication_pairs1, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title(f'Pie Chart for Protocol: {protocol} (Normal)')
    
    plt.subplot(122)
    plt.pie(counts2, labels=communication_pairs2, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title(f'Pie Chart for Protocol: {protocol} (Abnormal)')
    
    plt.show()

# Create a line chart subplot
def create_line_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol):
    plt.figure(figsize=(12, 6))
    plt.subplot(121)
    plt.plot(range(len(communication_pairs1)), counts1, marker='o')
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Line Chart for Protocol: {protocol} (Normal)')
    plt.xticks(range(len(communication_pairs1)), communication_pairs1, rotation='vertical')
    plt.tight_layout()
    
    plt.subplot(122)
    plt.plot(range(len(communication_pairs2)), counts2, marker='o')
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Line Chart for Protocol: {protocol} (Abnormal)')
    plt.xticks(range(len(communication_pairs2)), communication_pairs2, rotation='vertical')
    plt.tight_layout()
    
    plt.show()

# Create a bar chart subplot
def create_bar_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol):
    plt.figure(figsize=(12, 6))
    plt.subplot(121)
    plt.bar(range(len(communication_pairs1)), counts1)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Bar Chart for Protocol: {protocol} (Normal)')
    plt.xticks(range(len(communication_pairs1)), communication_pairs1, rotation='vertical')
    plt.tight_layout()
    
    plt.subplot(122)
    plt.bar(range(len(communication_pairs2)), counts2)
    plt.xlabel('Communication Pairs')
    plt.ylabel('Count')
    plt.ylim(0,200)
    plt.title(f'Bar Chart for Protocol: {protocol} (Abnormal)')
    plt.xticks(range(len(communication_pairs2)), communication_pairs2, rotation='vertical')
    plt.tight_layout()
    
    plt.show()

# Create a treemap chart subplot
def create_treemap_subplot(communication_pairs1, counts1, communication_pairs2, counts2, protocol):
    data1 = [{'Label': pair, 'Count': count} for pair, count in zip(communication_pairs1, counts1)]
    fig1 = px.treemap(data1, path=['Label'], values='Count')
    fig1.update_layout(title=f'Treemap for {protocol.upper()} Address Communication Counts (Normal)')
    
    data2 = [{'Label': pair, 'Count': count} for pair, count in zip(communication_pairs2, counts2)]
    fig2 = px.treemap(data2, path=['Label'], values='Count')
    fig2.update_layout(title=f'Treemap for {protocol.upper()} Address Communication Counts (Abnormal)')
    
    fig1.show()
    fig2.show()

if __name__ == "__main__":
    while True:
        data_source = input("Select data source (1 for sniff, pcap for pcap files, quit to exit): ")

        if data_source == 'quit':
            break
        elif data_source == '1':
            address_type = input("Enter for IP/MAC address ('ip', 'mac'): ")
            protocol = ""
            if address_type == AddressType.IP.value:
                protocol = input("Enter the protocol to capture (e.g., 'ip', 'tcp', 'udp'): ")
            elif address_type == AddressType.MAC.value:
                protocol = AddressType.MAC.value
            else:
                print("Invalid choice. Please select a valid IP/MAC address type (ip/mac).")
                continue

            graph_type = input("Enter the graph type (scatter/pie/line/bar/treemap/quit): ")

            communication_counts = analyze_packets(protocol, address_type)
            if communication_counts:
                if graph_type == GraphType.QUIT.value:
                    break
                create_graph_subplot(communication_counts, communication_counts, protocol, graph_type)
            else:
                print("No data to plot.")
        elif data_source == 'pcap':
            pcap_files = []
            communication_counts1 = {}
            communication_counts2 = {}
            for i in range(2):
                pcap_file = input(f"Enter the name of the {['Normal', 'Abnormal'][i]} file {i + 1}: ")
                pcap_files.append(pcap_file)
                address_type = input("Enter for IP/MAC address ('ip', 'mac'): ")

                if address_type == AddressType.IP.value:
                    protocol = input(f"Enter the protocol to analyze for {['Normal', 'Abnormal'][i]} (e.g., 'ip', 'tcp', 'udp', 'icmp'): ")
                    communication_counts = analyze_packets(protocol, address_type)
                elif address_type == AddressType.MAC.value:
                    protocol = AddressType.MAC.value
                    communication_counts = analyze_packets_mac()
                else:
                    print("Invalid choice. Please select a valid IP/MAC address type (ip/mac).")
                    continue

                if i == 0:
                    communication_counts1 = communication_counts
                else:
                    communication_counts2 = communication_counts

            if communication_counts1 and communication_counts2:
                while True:
                    graph_type = input("Enter the graph type (scatter/pie/line/bar/treemap/quit): ")
                    if graph_type == GraphType.QUIT.value:
                        sys.exit(0)
                    if graph_type in [GraphType.SCATTER.value, GraphType.PIE.value, GraphType.LINE.value, GraphType.BAR.value, GraphType.TREEMAP.value]:
                        create_graph_subplot(communication_counts1, communication_counts2, protocol, graph_type)
                    else:
                        print("Invalid graph type. Please select a valid graph type (scatter/pie/line/bar/treemap/quit).")
            else:
                print("No data to plot.")
        else:
            print("Invalid choice. Please select a valid data source (1/pcap/quit).")