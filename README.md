# Network Tools Suite 🛠️

Набор Python-скриптов для анализа и мониторинга сетевой активности.  
**Включает:** ARP-сканер, ICMP-пинг, порт-сканер и сниффер пакетов с GUI.

---

## 📦 Установка

### Требования:

- Python 3.8+
  
- Linux (рекомендуется) / Windows / macOS

1. Клонируйте репозиторий:
   
   ```bash
   git clone https://github.com/yourusername/network-tools.git
   cd network-tools
   ```
   
2. Установите зависимости:
   
   ```bash
   pip install -r requirements.txt
   ```
   
## 🚀 Скрипты

1. ARP Scanner (```arp-scan.py```)
   
   Обнаружение устройств в локальной сети через ARP-запросы.
   
   **Особенности:**
   
   - Автоматическое определение подсети
   - Вывод IP и MAC-адресов

   **Запуск:**
   
   ```bash
   sudo python3 arp-scan.py
   ```

   **Пример результата:**
   
   ```
   IP: 192.168.1.1 MAC: 00:11:22:33:44:55
   IP: 192.168.1.101 MAC: aa:bb:cc:dd:ee:ff
   ```
   
3. ICMP Ping (```icmp_scan.py```)

   Проверка доступности хоста через ICMP Echo Request.
   **Запуск:**
   
   ```bash
   python3 icmp_scan.py
   ```

   **Пример вывода:**
   
   ```
   IP: 192.168.0.103 is alive
   ```
   
5. Port Scanner (portscan.py)

   Сканирование портов на указанных хостах.
   
   **Поддерживает:**

   - SYN-сканирование

   - Определение статуса портов: OPEN/CLOSED/FILTERED

   **Запуск:**
   
   ```bash
   sudo python3 portscan.py
   ```
   
   Пример ввода:
   
   ```
   Enter target IPs (comma-separated): 192.168.0.1, 192.168.0.2
   Enter ports (comma-separated): 22, 80, 443
   ```

   **Пример вывода:**
   
   ```
   Scanning 192.168.0.1:
   [+] Port    22 → OPEN
   [+] Port    80 → OPEN
   [+] Port   443 → OPEN

   Scanning 192.168.0.2:
   WARNING: MAC address to reach destination not found. Using broadcast.
   [!] Port    22 → NO RESPONSE
   WARNING: MAC address to reach destination not found. Using broadcast.
   [!] Port    80 → NO RESPONSE
   WARNING: MAC address to reach destination not found. Using broadcast.
   [!] Port   443 → NO RESPONSE
   ```
   
7. Packet Sniffer(```sniffer_v1.1.py```)
   
   Графический сниффер пакетов с фильтрацией.
   
   **Функции:**
   
   - Перехват TCP/UDP/ICMP трафика
     
   - Фильтры: TCP SYN, UDP, ICMP, кастомные BPF
     
   - Сохранение в PCAP-файл

   **Запуск:**
   
   ```bash
   sudo -E env "PATH=$PATH" python3 sniffer_v1.1.py
   ```

   **Пример вывода:**
   
   ![Снимок экрана_20250209_000800](https://github.com/user-attachments/assets/390ec642-4451-4e33-a73f-e9e7518ae12b)
   
## ⚠️ Важно

- Для работы с RAW-сокетами требуются права root.
  
- Используйте инструменты только в тестовых сетях с разрешения администратора.
  
- Не все функции могут работать в Windows (например, ARP-сканер).


