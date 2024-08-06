from scapy.all import *
import matplotlib.pyplot as plt
import sys
from fpdf import FPDF
import plotly.graph_objects as go

def filter_packets(pcap_file=None):
    if pcap_file:
        packets = rdpcap(pcap_file)
    else:
        packets = sniff(count=1000, filter="tcp", store=1)
    
    return packets

def analyze_flags(tcp_packets):
    syn_count = 0
    ack_count = 0
    fin_count = 0

    for packet in tcp_packets:
        if TCP in packet:  # Check if the packet has a TCP layer
            if packet[TCP].flags & 0x02:  # Check for SYN flag
                syn_count += 1
            if packet[TCP].flags & 0x10:  # Check for ACK flag
                ack_count += 1
            if packet[TCP].flags & 0x01:  # Check for FIN flag
                fin_count += 1

    return syn_count, ack_count, fin_count

def calculate_jitter(tcp_packets):
    jitter = [tcp_packets[i + 1].time - tcp_packets[i].time for i in range(len(tcp_packets) - 1)]
    return jitter

def generate_bar_chart(data, title):
    labels = ['SYN', 'ACK', 'FIN']
    plt.bar(labels, data)
    plt.title(title)
    plt.ylim(0, 1800)
    plt.xlabel('TCP Flags')
    plt.ylabel('Count')
    plt.show()

def generate_line_chart(data, title):
    plt.plot(range(len(data)), data)
    plt.title(title)
    plt.ylim(0, 1800)
    plt.xlabel('TCP Flags')
    plt.ylabel('Count')
    plt.show()

def generate_pie_chart(data, title):
    labels = ['SYN', 'ACK', 'FIN']
    plt.pie(data, autopct='%1.1f%%', pctdistance=1.1, labeldistance=1.2)
    plt.title(title)
    plt.legend(labels, loc="upper right", bbox_to_anchor=(1, 1))
    plt.show()

def generate_scatter_chart(data, title):
    labels = ['SYN', 'ACK', 'FIN']
    plt.scatter(labels, data)
    plt.title(title)
    plt.ylim(0, 1800)
    plt.xlabel('TCP Flags')
    plt.ylabel('Count')
    plt.show()

def generate_area_chart(data, title):
    x = ['SYN', 'ACK', 'FIN']
    y = data
    fig, ax = plt.subplots()
    ax.fill_between(x, y, 0, alpha=0.5)
    plt.title(title)
    plt.ylim(0, 1800)
    plt.xlabel('TCP Flags')
    plt.ylabel('Count')
    plt.show()

def compare_jitter(jitter1, jitter2):
    # Perform jitter comparison here
    # You can calculate statistics, perform hypothesis tests, or visualize the comparison as needed
    jitter1 = [float(j) for j in jitter1]
    jitter2 = [float(j) for j in jitter2]

    # Create a box plot to compare jitter distributions
    plt.boxplot([jitter1, jitter2], labels=['Normal', 'Abnormal'])
    plt.title('Jitter Comparison')
    plt.ylabel('Jitter (seconds)')
    plt.show()

def generate_pdf_report(pcap_files, data):
    for i, pcap_file in enumerate(pcap_files):
        pdf = FPDF(orientation='L', unit='mm', format='letter')
        pdf.add_page()

        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Analysis for {}".format(pcap_file), ln=True, align='L')
        pdf.ln(10)

        pdf.cell(200, 10, txt="Flag Counts:", ln=True, align='L')
        pdf.set_font("Arial", size=10)
        pdf.ln(10)

        pdf.cell(200, 10, txt="Flag Counts:")
        pdf.ln(10)

        flag_data = [['Flag', 'Count']]
        flag_data.append(['SYN', data[i]['syn_count']])
        flag_data.append(['ACK', data[i]['ack_count']])
        flag_data.append(['FIN', data[i]['fin_count']])

        for row in flag_data:
            for item in row:
                pdf.cell(95, 10, txt=str(item), border=1)
            pdf.ln()

        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Jitter Analysis:", ln=True, align='L')
        pdf.ln(10)

        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="Jitter Analysis:")
        pdf.ln(10)

        jitter_data = [['Packet', 'Jitter (seconds)']]
        for j, jitter in enumerate(data[i]['jitter']):
            jitter_data.append([j + 1, jitter])

        for row in jitter_data:
            for item in row:
                pdf.cell(95, 10, txt=str(item), border=1)
            pdf.ln()

        pdf.output("pcap_report_{}.pdf".format(i))

if __name__ == '__main__':
    source_choice = input("Enter 'sniff' for sniffing packets or 'pcap' for pcap files: ")

    if source_choice == 'sniff':
        # Sniff packets here
        packets = sniff(count=1000, filter="tcp", store=1)
        syn_count, ack_count, fin_count = analyze_flags(packets)
        jitter = calculate_jitter(packets)
        data = {
            'syn_count': syn_count,
            'ack_count': ack_count,
            'fin_count': fin_count,
            'jitter': jitter,
            'source_type': 'Sniffed Packets',
        }
        while True:
            print("\nSelect a graph option to generate for Sniffed Packets:")
            print("1. Bar Chart for Flag Counts")
            print("2. Line Chart for Flag Counts")
            print("3. Pie Chart for Flag Distribution")
            print("4. Area Chart for Flag Counts")
            print("5. Scatter Chart for Flag Counts")
            print("6. Compare Jitter with Normal")
            print("7. Generate PDF Report")
            print("8. Quit")

            choice = input("Enter the number of your choice: ")

            if choice == '1':
                generate_bar_chart([data['syn_count'], data['ack_count'], data['fin_count']], 'Flag Counts (Sniffed Packets)')
            elif choice == '2':
                generate_line_chart([data['syn_count'], data['ack_count'], data['fin_count']], 'Flag Counts (Sniffed Packets)')
            elif choice == '3':
                generate_pie_chart([data['syn_count'], data['ack_count'], data['fin_count']], 'Flag Distribution (Sniffed Packets)')
            elif choice == '4':
                generate_area_chart([data['syn_count'], data['ack_count'], data['fin_count']], 'Flag Counts (Sniffed Packets)')
            elif choice == '5':
                generate_scatter_chart([data['syn_count'], data['ack_count'], data['fin_count']], 'Flag Counts Scatter (Sniffed Packets)')
            elif choice == '6':
                compare_jitter(data['jitter'], data['jitter'])
            elif choice == '7':
                generate_pdf_report(['Sniffed Packets'], [data])
            elif choice == '8':
                sys.exit(0)
            else:
                print("Invalid choice. Please select a valid option.")
    elif source_choice == 'pcap':
        pcap_files = []
        data = []
        while len(pcap_files) < 2:
            print(f"Select pcap file {len(pcap_files) + 1}:")
            pcap_file = input("Enter the name of the pcap file: ")
            pcap_files.append(pcap_file)
        
        for pcap_file in pcap_files:
            tcp_packets = filter_packets(pcap_file)
            syn_count, ack_count, fin_count = analyze_flags(tcp_packets)
            jitter = calculate_jitter(tcp_packets)
            data.append({
                'syn_count': syn_count,
                'ack_count': ack_count,
                'fin_count': fin_count,
                'jitter': jitter,
                'source_type': f'Pcap File: {pcap_file}',
            })

        while True:
            print("\nSelect a graph option to generate for the pcap files:")
            print("1. Bar Chart for Flag Counts (Normal)")
            print("2. Bar Chart for Flag Counts (Abnormal)")
            print("3. Line Chart for Flag Counts (Normal)")
            print("4. Line Chart for Flag Counts (Abnormal)")
            print("5. Pie Chart for Flag Distribution (Normal)")
            print("6. Pie Chart for Flag Distribution (Abnormal)")
            print("7. Area Chart for Flag Counts (Normal)")
            print("8. Area Chart for Flag Counts (Abnormal)")
            print("9. Scatter Chart for Flag Counts (Normal)")
            print("10. Scatter Chart for Flag Counts (Abnormal)")
            print("11. Compare Jitter (Normal vs. Abnormal)")
            print("12. Generate PDF Report")
            print("13. Quit")

            choice = input("Enter the number of your choice: ")

            if choice == '1':
                generate_bar_chart([data[0]['syn_count'], data[0]['ack_count'], data[0]['fin_count']], 'Flag Counts (Normal)')
            elif choice == '2':
                generate_bar_chart([data[1]['syn_count'], data[1]['ack_count'], data[1]['fin_count']], 'Flag Counts (Abnormal)')
            elif choice == '3':
                generate_line_chart([data[0]['syn_count'], data[0]['ack_count'], data[0]['fin_count']], 'Flag Counts (Normal)')
            elif choice == '4':
                generate_line_chart([data[1]['syn_count'], data[1]['ack_count'], data[1]['fin_count']], 'Flag Counts (Abnormal)')
            elif choice == '5':
                generate_pie_chart([data[0]['syn_count'], data[0]['ack_count'], data[0]['fin_count']], 'Flag Distribution (Normal)')
            elif choice == '6':
                generate_pie_chart([data[1]['syn_count'], data[1]['ack_count'], data[1]['fin_count']], 'Flag Distribution (Abnormal)')
            elif choice == '7':
                generate_area_chart([data[0]['syn_count'], data[0]['ack_count'], data[0]['fin_count']], 'Flag Counts (Normal)')
            elif choice == '8':
                generate_area_chart([data[1]['syn_count'], data[1]['ack_count'], data[1]['fin_count']], 'Flag Counts (Abnormal)')
            elif choice == '9':
                generate_scatter_chart([data[0]['syn_count'], data[0]['ack_count'], data[0]['fin_count']], 'Flag Counts Scatter (Normal)')
            elif choice == '10':
                generate_scatter_chart([data[1]['syn_count'], data[1]['ack_count'], data[1]['fin_count']], 'Flag Counts Scatter (Abnormal)')
            elif choice == '11':
                compare_jitter(data[0]['jitter'], data[1]['jitter'])
            elif choice == '12':
                generate_pdf_report(pcap_files, data)
            elif choice == '13':
                sys.exit(0)
            else:
                print("Invalid choice. Please select a valid option.")
    else:
        print("Invalid choice. Please enter '1' for sniffing packets or 'pcap' for pcap files.")
        sys.exit(1)