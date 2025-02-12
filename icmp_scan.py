from scapy.all import IP, ICMP, sr1

target_ip = "192.168.0.103" # заменить на целевой IP адрес

# Создаем пакет ICMP
icmp = IP(dst=target_ip)/ICMP()

# Отправляем запрос и получаем ответ
result = sr1(icmp, timeout=0.1, verbose=0)

# Обрабатываем результаты
if result:
    if result.haslayer(ICMP):
        if result[ICMP].type == 0: # ICMP Echo Reply
            print(f"IP: {result[IP].src} is alive")
        elif result.ICMP.type == 3: # ICMP Destination Unreachable
            print(f"IP: {result[IP].src} is not responding")
else:
    print(f"IP: {target_ip} is not responding")