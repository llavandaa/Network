import sys
from scapy.all import get_if_list, sniff, wrpcap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog, 
    QInputDialog, QMessageBox
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QTextCursor

# Константы
DEFAULT_FILTERS = ["TCP SYN", "UDP", "ICMP", "Custom"]
BPF_FILTER_MAP = {
    "TCP SYN": "tcp[13] == 2",
    "UDP": "udp",
    "ICMP": "icmp"
}

class SnifferThread(QThread):
    """Поток для захвата сетевых пакетов"""
    packet_received = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._is_running = True

    def run(self):
        """Основной метод потока"""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda pkt: self.packet_received.emit(pkt),
                stop_filter=lambda _: not self._is_running,
                store=False
            )
        except Exception as e:
            self.error_occurred.emit(f"Sniffing error: {str(e)}")

    def stop(self):
        """Безопасная остановка потока"""
        self._is_running = False
        if self.isRunning():
            self.wait(2000)  # Ожидание завершения до 2 секунд

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packets = []
        self.sniffer_thread = None
        self.current_filter = ""
        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        """Инициализация интерфейса"""
        self.setWindowTitle("Advanced Packet Sniffer")
        self.resize(1000, 800)
        
        # Виджеты
        self.interface_combo = QComboBox()
        self.filter_combo = QComboBox()
        self.log_area = QTextEdit()
        self.start_btn = QPushButton("Start Sniffing")
        self.save_btn = QPushButton("Save to File")
        self.clear_btn = QPushButton("Clear Log")

        # Настройка элементов
        self.interface_combo.addItems(get_if_list())
        self.filter_combo.addItems(DEFAULT_FILTERS)
        self.log_area.setReadOnly(True)
        self.log_area.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        # Макет
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_combo)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.save_btn)
        control_layout.addWidget(self.clear_btn)

        main_layout = QVBoxLayout()
        main_layout.addLayout(control_layout)
        main_layout.addWidget(self.log_area)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def setup_connections(self):
        """Настройка сигналов и слотов"""
        self.filter_combo.currentIndexChanged.connect(self.handle_filter_change)
        self.start_btn.clicked.connect(self.toggle_sniffing)
        self.save_btn.clicked.connect(self.save_packets)
        self.clear_btn.clicked.connect(self.clear_log)

    def handle_filter_change(self, index):
        """Обработка изменения фильтра"""
        if self.filter_combo.itemText(index) == "Custom":
            custom_filter, ok = QInputDialog.getText(
                self, "Custom Filter", "Enter BPF filter:"
            )
            if ok and custom_filter:
                self.current_filter = custom_filter
            else:
                self.filter_combo.setCurrentIndex(0)

    def toggle_sniffing(self):
        """Переключение режима сниффинга"""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.stop_sniffing()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        """Запуск сниффера"""
        interface = self.interface_combo.currentText()
        filter_text = self.get_bpf_filter()

        if not interface:
            QMessageBox.warning(self, "Error", "No network interface selected!")
            return

        self.sniffer_thread = SnifferThread(interface, filter_text)
        self.sniffer_thread.packet_received.connect(self.log_packet)
        self.sniffer_thread.error_occurred.connect(self.show_error)
        self.sniffer_thread.start()
        self.start_btn.setText("Stop Sniffing")
        self.log_area.append(f"[*] Starting capture on {interface} with filter: {filter_text}")

    def stop_sniffing(self):
        """Остановка сниффера"""
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.start_btn.setText("Start Sniffing")
            self.log_area.append("[*] Capture stopped")

    def get_bpf_filter(self):
        """Получение текущего BPF-фильтра"""
        selected_filter = self.filter_combo.currentText()
        return BPF_FILTER_MAP.get(selected_filter, self.current_filter)

    def log_packet(self, packet):
        """Логирование пакета"""
        self.packets.append(packet)
        self.log_area.moveCursor(QTextCursor.MoveOperation.End)
        self.log_area.insertPlainText(packet.summary() + "\n")

    def save_packets(self):
        """Сохранение пакетов в файл"""
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets to save!")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "", "PCAP Files (*.pcap)"
        )
        if filename:
            wrpcap(filename, self.packets)
            QMessageBox.information(self, "Success", f"Saved {len(self.packets)} packets to {filename}")

    def clear_log(self):
        """Очистка лога"""
        self.log_area.clear()
        self.packets.clear()

    def show_error(self, message):
        """Отображение ошибок"""
        QMessageBox.critical(self, "Error", message)
        self.stop_sniffing()

    def closeEvent(self, event):
        """Обработка закрытия окна"""
        self.stop_sniffing()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())