import sys
from scapy.all import get_if_list, sniff, wrpcap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog, QInputDialog
)
from PyQt6.QtCore import QThread, pyqtSignal

class SnifferThread(QThread):
    packet_received = pyqtSignal(object)  # Сигнал для передачи пакета

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = True

    def run(self):
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: self.packet_received.emit(pkt),
            stop_filter=lambda _: not self.is_running
        )

    def stop(self):
        self.is_running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt Packet Sniffer")
        self.packets = []
        self.sniffer_thread = None

        # Виджеты
        self.interface_combo = QComboBox()
        self.filter_combo = QComboBox()
        self.log_area = QTextEdit()
        self.start_btn = QPushButton("Start Sniffing")
        self.save_btn = QPushButton("Save to File")

        self.init_ui()

    def init_ui(self):
        # Настройка интерфейсов
        interfaces = get_if_list()
        self.interface_combo.addItems(interfaces)
        if "lo" in interfaces:  # Выбираем не loopback по умолчанию
            self.interface_combo.setCurrentIndex(1)

        # Настройка фильтров
        self.filter_combo.addItems(["TCP SYN", "UDP", "ICMP", "Custom"])
        self.filter_combo.currentIndexChanged.connect(self.handle_filter_change)

        # Кнопки
        self.start_btn.clicked.connect(self.toggle_sniffing)
        self.save_btn.clicked.connect(self.save_packets)

        # Макет
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_combo)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.save_btn)

        main_layout = QVBoxLayout()
        main_layout.addLayout(control_layout)
        main_layout.addWidget(self.log_area)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def handle_filter_change(self, index):
        if self.filter_combo.itemText(index) == "Custom":
            custom_filter, ok = QInputDialog.getText(
                self, "Custom Filter", "Enter BPF filter:"
            )
            if ok:
                self.current_filter = custom_filter
            else:
                self.filter_combo.setCurrentIndex(0)

    def toggle_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            # Остановка сниффера
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.start_btn.setText("Start Sniffing")
        else:
            # Запуск сниффера
            interface = self.interface_combo.currentText()
            filter_text = self.get_bpf_filter()
            
            self.sniffer_thread = SnifferThread(interface, filter_text)
            self.sniffer_thread.packet_received.connect(self.log_packet)
            self.sniffer_thread.start()
            self.start_btn.setText("Stop Sniffing")

    def get_bpf_filter(self):
        filter_map = {
            "TCP SYN": "tcp[13] == 2",
            "UDP": "udp",
            "ICMP": "icmp",
            "Custom": self.current_filter if hasattr(self, "current_filter") else ""
        }
        return filter_map.get(self.filter_combo.currentText(), "")

    def log_packet(self, packet):
        self.packets.append(packet)
        self.log_area.append(packet.summary())

    def save_packets(self):
        if not self.packets:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "", "PCAP Files (*.pcap)"
        )
        if filename:
            wrpcap(filename, self.packets)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())