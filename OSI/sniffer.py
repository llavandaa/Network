from scapy.all import *

# Фильтр BPF для захвата TCP SYN пакетов (без SYN-ACK)
bpf_filter = "tcp and tcp[13] == 2"  # 13-й байт заголовка TCP, значение 0x02 (SYN)

# Захват пакетов
pkts = sniff(
    iface="enp3s0", 
    filter=bpf_filter, 
    prn=lambda x: x.summary()
)

# !!! доработать, добавить функционал(переключение интерфесов(отобразить для выборки), фильтров, сохранение в файл, графический интерфейс, отправка на почту)

