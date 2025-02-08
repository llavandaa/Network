from scapy.all import ARP, Ether, srp

target_ip = "192.168.0.0/24" # Заменить на IP-адрес вашей сети
# Узнать адрес сети: ip route | grep default | awk '{print $3}' | cut -d'.' -f1-3

############################################
# Добавить автоматическое определение сети #
############################################

# Создаем ARP запрос
arp = ARP(pdst=target_ip)

# Создаем Ethernet пакет
eth = Ether(dst="ff:ff:ff:ff:ff:ff")

# Создаем комплексный пакет
packet = eth / arp

# Отправляем запрос и получаем ответы
# SRP - Send and Receive Packets
result = srp(packet, timeout=2, verbose=0)[0]

# Обрабатываем результаты
for sent, received in result:
    print(f"IP: {received.psrc} MAC: {received.hwsrc}")

# Запускаем скан
# sudo python3 arp-scan.py