import sys
import scapy


def handle_packet(packet, log):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        scr_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        log.write(f'TCP connection : {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n')


def main(interface, verbose):
    logfile_name = f'sniffer_{interface}_log.txt'

    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                '''
                prn = print
                pkt is a Scapy packet object, typically an instance of scapy.packet.Packet.
                It can represent different network layers, such as:
                Ether (Ethernet frame)
                IP (IP packet)
                TCP (TCP segment)
                UDP (UDP datagram)
                ICMP (ICMP message)
                '''
                scapy.all.sniff(iface = interface, prn = lambda pkt: handle_packet(pkt, logfile),
                    store = 0, verbose = verbose)
        except:
            pass


if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print('usage : python 0hagaScapy.py 1<interface> 2[verbose]')

    verbose = False

    if len(sys.argv) == 3 and sys.argv[2].lower() == 'verbose':
        main(sys.argv[1], verbose)
