from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import numpy as np

# Lists to store packet information
src_ip_list = []       # List to store source IP addresses
dst_ip_list = []       # List to store destination IP addresses
protocol_list = []    # List to store IP protocols

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Collect source IPs, destination IPs, and protocols
        src_ip_list.append(src_ip)
        dst_ip_list.append(dst_ip)
        protocol_list.append(protocol)

def generate_pdf_summary():
    doc = SimpleDocTemplate("packet_ip_summary.pdf", pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Generate a paragraph for source IPs
    src_ip_counts = Counter(src_ip_list)
    elements.append(Paragraph("Source IP Counts:", styles["Heading1"]))
    for ip, count in src_ip_counts.items():
        elements.append(Paragraph(f"Source IP: {ip}, Count: {count}", styles["Normal"]))
    elements.append(Spacer(1, 12))  # Add some space between sections

    # Generate a paragraph for destination IPs
    dst_ip_counts = Counter(dst_ip_list)
    elements.append(Paragraph("Destination IP Counts:", styles["Heading1"]))
    for ip, count in dst_ip_counts.items():
        elements.append(Paragraph(f"Destination IP: {ip}, Count: {count}", styles["Normal"]))
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
    # Generate a bar graph
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
    # Generate a line graph
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
    # Generate a scatter plot
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
        src_ip_counts = Counter(src_ip_list)
        dst_ip_counts = Counter(dst_ip_list)
        protocol_counts = Counter(protocol_list)

        generate_bar_graph(src_ip_counts, "Source IP Counts (Bar)", "Source IP", "Count", "source_ip_bar.png")
        generate_line_graph(src_ip_counts, "Source IP Counts (Line)", "Source IP", "Count", "source_ip_line.png")
        generate_scatter_graph(src_ip_counts, "Source IP Counts (Scatter)", "Source IP", "Count", "source_ip_scatter.png")

        generate_bar_graph(dst_ip_counts, "Destination IP Counts (Bar)", "Destination IP", "Count", "destination_ip_bar.png")
        generate_line_graph(dst_ip_counts, "Destination IP Counts (Line)", "Destination IP", "Count", "destination_ip_line.png")
        generate_scatter_graph(dst_ip_counts, "Destination IP Counts (Scatter)", "Destination IP", "Count", "destination_ip_scatter.png")

        generate_bar_graph(
            protocol_counts,
            "Protocol Counts (Bar)",
            "Protocol",
            "Count",
            "protocol_ip_bar.png"
        )
        generate_line_graph(
            protocol_counts,
            "Protocol Counts (Line)",
            "Protocol",
            "Count",
            "protocol_ip_line.png"
        )
        generate_scatter_graph(
            protocol_counts,
            "Protocol Counts (Scatter)",
            "Protocol",
            "Count",
            "protocol_ip_scatter.png"
        )

        generate_pdf_summary()

        print("Packet analysis, graph generation, and PDF generation complete.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()