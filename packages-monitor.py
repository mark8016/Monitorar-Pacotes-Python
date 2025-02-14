from scapy.all import *

# Função que será chamada a cada pacote capturado
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Pacote: {ip_src} -> {ip_dst}, Protocolo: {protocol}")

        # Detecção de possíveis ataques (exemplo simples)
        if packet.haslayer(TCP):
            if packet[TCP].flags == 'S':  # Pacote SYN - possível tentativa de escaneamento
                print(f"[ALERTA] Pacote SYN detectado de {ip_src}")

# Captura de pacotes em tempo real
sniff(prn=packet_callback, store=0)
