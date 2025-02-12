import sys
import re
from scapy.all import get_if_list, sniff, wrpcap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTextEdit, QFileDialog, 
    QInputDialog, QMessageBox, QDockWidget
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QSettings
from PyQt6.QtGui import QTextCursor, QColor, QSyntaxHighlighter, QTextCharFormat, QFont

# Константы и настройки
DEFAULT_FILTERS = ["TCP SYN", "UDP", "ICMP", "Custom"]
BPF_FILTER_MAP = {
    "TCP SYN": "tcp[13] == 2",
    "UDP": "udp",
    "ICMP": "icmp"
}
SETTINGS = QSettings("PacketSniffer", "MainWindow")

LANGUAGES = {
    "en": {
        "window_title": "Advanced Packet Sniffer v1.2.0",
        "interface": "Interface:",
        "filter": "Filter:",
        "start_btn": "Start Sniffing",
        "save_btn": "Save to File",
        "clear_btn": "Clear Log",
        "theme_dark": "Dark Theme",
        "theme_light": "Light Theme",
        "language_en": "English",
        "language_ru": "Russian",
        "details": "Packet Details",
        "errors": {
            "no_interface": "No network interface selected!",
            "no_packets": "No packets to save!",
            "sniff_error": "Sniffing error: {}"
        }
    },
    "ru": {
        "window_title": "Advanced Packet Sniffer v1.2.0",
        "interface": "Интерфейс:",
        "filter": "Фильтр:",
        "start_btn": "Начать захват",
        "save_btn": "Сохранить в файл",
        "clear_btn": "Очистить лог",
        "theme_dark": "Тёмная тема",
        "theme_light": "Светлая тема",
        "language_en": "Английский",
        "language_ru": "Русский",
        "details": "Детали пакета",
        "errors": {
            "no_interface": "Интерфейс не выбран!",
            "no_packets": "Нет пакетов для сохранения!",
            "sniff_error": "Ошибка сниффинга: {}"
        }
    }
}

THEMES = {
    "dark": """
        QWidget { background-color: #2E2E2E; color: #FFFFFF; }
        QTextEdit { background-color: #1E1E1E; }
        QComboBox, QPushButton { background-color: #3E3E3E; }
        QDockWidget::title { background: #3E3E3E; }
    """,
    "light": """
        QWidget { background-color: #FFFFFF; color: #000000; }
        QTextEdit { background-color: #F0F0F0; }
        QComboBox, QPushButton { background-color: #E0E0E0; }
    """
}

class SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlight_rules = []
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keywords = ["Ether", "IP", "TCP", "UDP", "ICMP"]
        for word in keywords:
            self.highlight_rules.append((rf'\b{word}\b', keyword_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlight_rules:
            expression = re.compile(pattern)
            for match in expression.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)

class SnifferThread(QThread):
    packet_received = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._is_running = True

    def run(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda pkt: self.packet_received.emit(pkt),
                stop_filter=lambda _: not self._is_running,
                store=False
            )
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self._is_running = False
        if self.isRunning():
            self.wait(2000)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packets = []
        self.sniffer_thread = None
        self.current_filter = ""
        self.current_lang = SETTINGS.value("language", "en")
        self.current_theme = SETTINGS.value("theme", "light")
        self.init_ui()
        self.setup_connections()
        self.load_settings()
    
    def load_settings(self):
        pass

    def init_ui(self):
        self.setWindowTitle(LANGUAGES[self.current_lang]["window_title"])
        self.resize(1000, 800)
        
        # Основные виджеты
        self.interface_combo = QComboBox()
        self.filter_combo = QComboBox()
        self.log_area = QTextEdit()
        self.start_btn = QPushButton()
        self.save_btn = QPushButton()
        self.clear_btn = QPushButton()
        self.theme_btn = QPushButton()
        self.lang_btn = QPushButton()

        # Док-виджет для деталей
        self.dock = QDockWidget(LANGUAGES[self.current_lang]["details"], self)
        self.details_area = QTextEdit()
        self.details_area.setReadOnly(True)
        self.dock.setWidget(self.details_area)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)

        # Настройки
        self.interface_combo.addItems(get_if_list())
        self.filter_combo.addItems(DEFAULT_FILTERS)
        self.log_area.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.details_area.setFont(QFont("Consolas", 10))
        SyntaxHighlighter(self.details_area.document())

        # Панель управления
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel(LANGUAGES[self.current_lang]["interface"]))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(QLabel(LANGUAGES[self.current_lang]["filter"]))
        control_layout.addWidget(self.filter_combo)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.save_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.theme_btn)
        control_layout.addWidget(self.lang_btn)

        main_layout = QVBoxLayout()
        main_layout.addLayout(control_layout)
        main_layout.addWidget(self.log_area)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.update_ui_text()
        self.apply_theme()

    def setup_connections(self):
        self.filter_combo.currentIndexChanged.connect(self.handle_filter_change)
        self.start_btn.clicked.connect(self.toggle_sniffing)
        self.save_btn.clicked.connect(self.save_packets)
        self.clear_btn.clicked.connect(self.clear_log)
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.lang_btn.clicked.connect(self.toggle_language)
        self.log_area.selectionChanged.connect(self.show_packet_details)

    def update_ui_text(self):
        lang = LANGUAGES[self.current_lang]
        self.setWindowTitle(lang["window_title"])
        self.start_btn.setText(lang["start_btn"])
        self.save_btn.setText(lang["save_btn"])
        self.clear_btn.setText(lang["clear_btn"])
        self.theme_btn.setText(lang[f"theme_{self.current_theme}"])
        self.lang_btn.setText(lang["language_ru" if self.current_lang == "en" else "language_en"])
        self.dock.setWindowTitle(lang["details"])

    def apply_theme(self):
        self.setStyleSheet(THEMES[self.current_theme])

    def toggle_theme(self):
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        SETTINGS.setValue("theme", self.current_theme)
        self.theme_btn.setText(LANGUAGES[self.current_lang][f"theme_{self.current_theme}"])
        self.apply_theme()

    def toggle_language(self):
        self.current_lang = "ru" if self.current_lang == "en" else "en"
        SETTINGS.setValue("language", self.current_lang)
        self.update_ui_text()

    def show_packet_details(self):
        cursor = self.log_area.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText()
            for pkt in self.packets:
                if pkt.summary() in text:
                    self.details_area.setText(pkt.show(dump=True))
                    break

    def handle_filter_change(self, index):
        if self.filter_combo.itemText(index) == "Custom":
            custom_filter, ok = QInputDialog.getText(
                self, "Custom Filter", "Enter BPF filter:"
            )
            if ok and custom_filter:
                self.current_filter = custom_filter
            else:
                self.filter_combo.setCurrentIndex(0)

    def toggle_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.stop_sniffing()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        interface = self.interface_combo.currentText()
        filter_text = self.get_bpf_filter()

        if not interface:
            QMessageBox.warning(self, "Error", LANGUAGES[self.current_lang]["errors"]["no_interface"])
            return

        self.sniffer_thread = SnifferThread(interface, filter_text)
        self.sniffer_thread.packet_received.connect(self.log_packet)
        self.sniffer_thread.error_occurred.connect(self.show_error)
        self.sniffer_thread.start()
        self.start_btn.setText(LANGUAGES[self.current_lang]["start_btn"])
        self.log_area.append(f"[*] Starting capture on {interface} with filter: {filter_text}")

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.start_btn.setText(LANGUAGES[self.current_lang]["start_btn"])
            self.log_area.append("[*] Capture stopped")

    def get_bpf_filter(self):
        selected_filter = self.filter_combo.currentText()
        return BPF_FILTER_MAP.get(selected_filter, self.current_filter)

    def log_packet(self, packet):
        self.packets.append(packet)
        self.log_area.moveCursor(QTextCursor.MoveOperation.End)
        self.log_area.insertPlainText(packet.summary() + "\n")

    def save_packets(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", LANGUAGES[self.current_lang]["errors"]["no_packets"])
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "", "PCAP Files (*.pcap)"
        )
        if filename:
            wrpcap(filename, self.packets)
            QMessageBox.information(self, "Success", f"Saved {len(self.packets)} packets to {filename}")

    def clear_log(self):
        self.log_area.clear()
        self.packets.clear()

    def show_error(self, message):
        QMessageBox.critical(self, "Error", LANGUAGES[self.current_lang]["errors"]["sniff_error"].format(message))
        self.stop_sniffing()

    def closeEvent(self, event):
        self.stop_sniffing()
        SETTINGS.setValue("geometry", self.saveGeometry())
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())