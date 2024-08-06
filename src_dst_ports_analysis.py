from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Lists to store packet information
src_port_list = []    # List to store source ports
dst_port_list = []    # List to store destination ports
protocol_list = []    # List to store IP protocols

def packet_handler(packet):
    if IP in packet:
        src_port = None
        dst_port = None
        protocol = packet[IP].proto

        # Check if the packet has a transport layer (TCP or UDP)
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Collect source ports, destination ports, and protocols
        src_port_list.append(src_port)
        dst_port_list.append(dst_port)
        protocol_list.append(protocol)

def generate_pdf_summary():
    doc = SimpleDocTemplate("packet_port_summary.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Generate a paragraph for source ports
    src_port_counts = Counter(src_port_list)
    elements.append(Paragraph("Source Port Counts:", styles["Heading1"]))
    for port, count in src_port_counts.items():
        elements.append(Paragraph(f"Source Port: {port}, Count: {count}", styles["Normal"]))
    elements.append(Spacer(1, 12))  # Add some space between sections

    # Generate a paragraph for destination ports
    dst_port_counts = Counter(dst_port_list)
    elements.append(Paragraph("Destination Port Counts:", styles["Heading1"]))
    for port, count in dst_port_counts.items():
        elements.append(Paragraph(f"Destination Port: {port}, Count: {count}", styles["Normal"]))
    elements.append(Spacer(1, 12))  # Add some space between sections

    # Generate a paragraph for protocols
    protocol_counts = Counter(protocol_list)
    elements.append(Paragraph("Protocol Counts:", styles["Heading1"]))
    for protocol, count in protocol_counts.items():
        elements.append(Paragraph(f"Protocol: {protocol}, Count: {count}", styles["Normal"]))
    elements.append(Spacer(1, 12))  # Add some space between sections

    doc.build(elements)

# Functions to generate bar, line, and scatter plots
# These functions create and save different types of graphs

def generate_bar_graph(data, title, x_label, y_label, filename):
    plt.figure(figsize=(8, 4))
    plt.bar(data.keys(), data.values())
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()

def generate_line_graph(data, title, x_label, y_label, filename):
    plt.figure(figsize=(8, 4))
    plt.plot(data.keys(), data.values(), marker='o')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()

def generate_scatter_graph(data, title, x_label, y_label, filename):
    plt.figure(figsize=(8, 4))
    plt.scatter(data.keys(), data.values(), c='blue', label=title, alpha=0.5)
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()

def main():
    pcap_file = 'Normal.pcap'  # Replace with the path to your pcap file

    try:
        # Read the pcap file and capture packets
        packets = rdpcap(pcap_file)

        # Process each packet and gather packet information
        for packet in packets:
            packet_handler(packet)

        # Generate individual graphs, a PDF summary, and save the graphs as images
        src_port_counts = Counter(src_port_list)
        dst_port_counts = Counter(dst_port_list)
        protocol_counts = Counter(protocol_list)

        generate_bar_graph(src_port_counts, "Source Port Counts (Bar)", "Source Port", "Count", "source_port_bar.png")
        generate_line_graph(src_port_counts, "Source Port Counts (Line)", "Source Port", "Count", "source_port_line.png")
        generate_scatter_graph(src_port_counts, "Source Port Counts (Scatter)", "Source Port", "Count", "source_port_scatter.png")

        generate_bar_graph(dst_port_counts, "Destination Port Counts (Bar)", "Destination Port", "Count", "destination_port_bar.png")
        generate_line_graph(dst_port_counts, "Destination Port Counts (Line)", "Destination Port", "Count", "destination_port_line.png")
        generate_scatter_graph(dst_port_counts, "Destination Port Counts (Scatter)", "Destination Port", "Count", "destination_port_scatter.png")

        generate_bar_graph(
            protocol_counts,
            "Protocol Counts (Bar)",
            "Protocol",
            "Count",
            "protocol_port_bar.png"
        )
        generate_line_graph(
            protocol_counts,
            "Protocol Counts (Line)",
            "Protocol",
            "Count",
            "protocol_port_line.png"
        )
        generate_scatter_graph(
            protocol_counts,
            "Protocol Counts (Scatter)",
            "Protocol",
            "Count",
            "protocol_port_scatter.png"
        )

        generate_pdf_summary()

        print("Packet analysis, graph generation, and PDF generation complete.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()