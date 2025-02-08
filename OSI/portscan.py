from scapy.all import IP, TCP, sr1

# Получаем список IP-адресов
ip_list = [ip.strip() for ip in input("Enter target IPs (comma-separated): ").split(',')]

# Получаем список портов
ports = list(map(int, input("Enter ports (comma-separated): ").split(',')))

for ip in ip_list:
    print(f"\nScanning {ip}:")
    for port in ports:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")# Создаем SYN-пакет
        
        response = sr1(packet, timeout=2, verbose=0)        # Отправляем пакет и получаем ответ
        
        # Анализ ответа
        if response and response.haslayer(TCP):
            if response[TCP].flags & 0x12:  # google говорит SYN-ACK (0x12 = 18)
                print(f"[+] Port {port:5} → OPEN")
            elif response[TCP].flags & 0x04:  # google говорит RST (0x04 = 4)
                print(f"[-] Port {port:5} → CLOSED")
            else:
                print(f"[?] Port {port:5} → UNEXPECTED FLAGS: {response[TCP].flags}")
        else:
            print(f"[!] Port {port:5} → NO RESPONSE")