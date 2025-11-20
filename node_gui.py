import sys
import asyncio
import json
from typing import Optional
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QDialog, QMessageBox, QListWidget, QListWidgetItem, QSpinBox, QLineEdit,
    QFormLayout, QComboBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QIcon, QColor, QTextCursor

from libp2p_pubsub_network import PubSubNode, ConfigManager, CryptoManager


class PeerAuthSignal(QObject):
    """Signal für Peer-Authentifizierungen"""
    auth_requested = pyqtSignal(str, str, str)  # node_id, public_key, peer_info


class NodeThread(QThread):
    """Thread um Node auszuführen"""

    auth_signal = pyqtSignal(str, str, str)

    def __init__(self, port: int, local_port: int, config_path: str):
        super().__init__()
        self.port = port
        self.local_port = local_port
        self.config_path = config_path
        self.node: Optional[PubSubNode] = None
        self.loop = None

    def run(self):
        """Node im Thread ausführen"""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            self.node = PubSubNode(
                port=self.port,
                local_port=self.local_port,
                config_path=self.config_path
            )

            # Message Handler für Auth-Requests patchen
            original_handle_peer_auth = self.node.message_handler._handle_peer_auth

            async def patched_handle_peer_auth(payload, node_id, peer_id):
                msg = json.loads(payload.decode('utf-8'))
                self.auth_signal.emit(
                    msg.get('node_id'),
                    msg.get('public_key'),
                    msg.get('peer_info', '')
                )

            self.node.message_handler._handle_peer_auth = patched_handle_peer_auth

            self.loop.run_until_complete(self.node.start())
            self.loop.run_forever()
        except Exception as e:
            print(f"Fehler in Node Thread: {e}")

    def stop(self):
        """Node stoppen"""
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)


class NodeGUI(QMainWindow):
    """Hauptfenster für Node GUI"""

    def __init__(self):
        super().__init__()
        self.node_thread: Optional[NodeThread] = None
        self.node = None
        self.pending_auth = {}

        self.init_ui()
        self.setup_timers()

    def init_ui(self):
        """GUI initialisieren"""
        self.setWindowTitle("libp2p PubSub Node Manager")
        self.setGeometry(100, 100, 1200, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Top Control Panel
        control_layout = QHBoxLayout()

        self.port_spinbox = QSpinBox()
        self.port_spinbox.setValue(10000)
        self.port_spinbox.setRange(1024, 65535)
        control_layout.addWidget(QLabel("Port:"))
        control_layout.addWidget(self.port_spinbox)

        self.local_port_spinbox = QSpinBox()
        self.local_port_spinbox.setValue(9000)
        self.local_port_spinbox.setRange(1024, 65535)
        control_layout.addWidget(QLabel("Local Port:"))
        control_layout.addWidget(self.local_port_spinbox)

        self.config_input = QLineEdit()
        self.config_input.setText("config.json")
        control_layout.addWidget(QLabel("Config:"))
        control_layout.addWidget(self.config_input)

        self.start_btn = QPushButton("Node Starten")
        self.start_btn.clicked.connect(self.start_node)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Node Stoppen")
        self.stop_btn.clicked.connect(self.stop_node)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)

        layout.addLayout(control_layout)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Tab 1: Node Info
        self.info_tab = QWidget()
        info_layout = QVBoxLayout(self.info_tab)

        self.node_info_text = QTextEdit()
        self.node_info_text.setReadOnly(True)
        info_layout.addWidget(QLabel("Node Informationen:"))
        info_layout.addWidget(self.node_info_text)

        self.tabs.addTab(self.info_tab, "Node Info")

        # Tab 2: Verbundene Nodes
        self.peers_tab = QWidget()
        peers_layout = QVBoxLayout(self.peers_tab)

        self.peers_list = QTreeWidget()
        self.peers_list.setColumnCount(3)
        self.peers_list.setHeaderLabels(["Node ID", "Peer ID", "Status"])
        peers_layout.addWidget(QLabel("Verbundene Nodes:"))
        peers_layout.addWidget(self.peers_list)

        self.tabs.addTab(self.peers_tab, "Verbundene Nodes")

        # Tab 3: Topics
        self.topics_tab = QWidget()
        topics_layout = QVBoxLayout(self.topics_tab)

        topics_control_layout = QHBoxLayout()

        self.topic_input = QLineEdit()
        self.topic_input.setPlaceholderText("Neuer Topic...")
        topics_control_layout.addWidget(self.topic_input)

        self.provide_topic_btn = QPushButton("Topic anbieten")
        self.provide_topic_btn.clicked.connect(self.provide_topic)
        self.provide_topic_btn.setEnabled(False)
        topics_control_layout.addWidget(self.provide_topic_btn)

        self.subscribe_topic_btn = QPushButton("Topic abonnieren")
        self.subscribe_topic_btn.clicked.connect(self.subscribe_topic)
        self.subscribe_topic_btn.setEnabled(False)
        topics_control_layout.addWidget(self.subscribe_topic_btn)

        topics_layout.addLayout(topics_control_layout)

        self.topics_tree = QTreeWidget()
        self.topics_tree.setColumnCount(3)
        self.topics_tree.setHeaderLabels(["Topic Name", "Provider Node ID", "Status"])
        topics_layout.addWidget(QLabel("Topics:"))
        topics_layout.addWidget(self.topics_tree)

        self.tabs.addTab(self.topics_tab, "Topics")

        # Tab 4: Authentifizierung
        self.auth_tab = QWidget()
        auth_layout = QVBoxLayout(self.auth_tab)

        self.pending_auth_list = QListWidget()
        auth_layout.addWidget(QLabel("Ausstehende Authentifizierungen:"))
        auth_layout.addWidget(self.pending_auth_list)

        auth_button_layout = QHBoxLayout()

        self.auth_accept_btn = QPushButton("Akzeptieren")
        self.auth_accept_btn.clicked.connect(self.accept_peer)
        auth_button_layout.addWidget(self.auth_accept_btn)

        self.auth_reject_btn = QPushButton("Ablehnen")
        self.auth_reject_btn.clicked.connect(self.reject_peer)
        auth_button_layout.addWidget(self.auth_reject_btn)

        auth_layout.addLayout(auth_button_layout)

        self.auth_details_text = QTextEdit()
        self.auth_details_text.setReadOnly(True)
        auth_layout.addWidget(QLabel("Details:"))
        auth_layout.addWidget(self.auth_details_text)

        self.tabs.addTab(self.auth_tab, "Authentifizierung")

        # Tab 5: Logs
        self.logs_tab = QWidget()
        logs_layout = QVBoxLayout(self.logs_tab)

        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        logs_layout.addWidget(self.logs_text)

        self.tabs.addTab(self.logs_tab, "Logs")

    def setup_timers(self):
        """Timer für UI Updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)  # Update jede Sekunde

    def start_node(self):
        """Node starten"""
        try:
            port = self.port_spinbox.value()
            local_port = self.local_port_spinbox.value()
            config_path = self.config_input.text()

            self.log(f"Starte Node auf Port {port}...")

            self.node_thread = NodeThread(port, local_port, config_path)
            self.node_thread.auth_signal.connect(self.handle_peer_auth)
            self.node_thread.start()

            # Warte bis Node initialisiert ist
            asyncio.sleep(2)
            self.node = self.node_thread.node

            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.provide_topic_btn.setEnabled(True)
            self.subscribe_topic_btn.setEnabled(True)
            self.port_spinbox.setEnabled(False)
            self.local_port_spinbox.setEnabled(False)
            self.config_input.setEnabled(False)

            self.log("Node erfolgreich gestartet!")
            self.update_node_info()

        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Fehler beim Starten: {e}")
            self.log(f"FEHLER: {e}")

    def stop_node(self):
        """Node stoppen"""
        try:
            self.log("Stoppe Node...")
            if self.node_thread:
                self.node_thread.stop()
                self.node_thread.wait(5000)

            self.node = None
            self.node_thread = None

            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.provide_topic_btn.setEnabled(False)
            self.subscribe_topic_btn.setEnabled(False)
            self.port_spinbox.setEnabled(True)
            self.local_port_spinbox.setEnabled(True)
            self.config_input.setEnabled(True)

            self.log("Node gestoppt!")

        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Fehler beim Stoppen: {e}")
            self.log(f"FEHLER: {e}")

    def provide_topic(self):
        """Topic anbieten"""
        if not self.node:
            QMessageBox.warning(self, "Warnung", "Node nicht aktiv!")
            return

        topic = self.topic_input.text().strip()
        if not topic:
            QMessageBox.warning(self, "Warnung", "Bitte Topic-Namen eingeben!")
            return

        try:
            asyncio.run_coroutine_threadsafe(
                self.node.provide_topic(topic),
                self.node_thread.loop
            )
            self.log(f"Topic angeboten: {topic}")
            self.topic_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Fehler: {e}")
            self.log(f"FEHLER beim Topic anbieten: {e}")

    def subscribe_topic(self):
        """Topic abonnieren"""
        if not self.node:
            QMessageBox.warning(self, "Warnung", "Node nicht aktiv!")
            return

        topic = self.topic_input.text().strip()
        if not topic:
            QMessageBox.warning(self, "Warnung", "Bitte Topic-Namen eingeben!")
            return

        try:
            asyncio.run_coroutine_threadsafe(
                self.node.subscribe(topic),
                self.node_thread.loop
            )
            self.log(f"Topic abonniert: {topic}")
            self.topic_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Fehler: {e}")
            self.log(f"FEHLER beim Topic abonnieren: {e}")

    def handle_peer_auth(self, node_id: str, public_key: str, peer_info: str):
        """Peer-Authentifizierung anfordern"""
        self.pending_auth[node_id] = {
            'node_id': node_id,
            'public_key': public_key,
            'peer_info': peer_info
        }

        item = QListWidgetItem(f"{node_id}")
        item.setData(Qt.ItemDataRole.UserRole, node_id)
        self.pending_auth_list.addItem(item)

        self.log(f"Neue Authentifizierungsanfrage: {node_id}")
        self.tabs.setCurrentIndex(4)  # Auth Tab

    def accept_peer(self):
        """Peer akzeptieren"""
        current_item = self.pending_auth_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warnung", "Bitte einen Peer auswählen!")
            return

        node_id = current_item.data(Qt.ItemDataRole.UserRole)
        peer_data = self.pending_auth[node_id]

        try:
            self.node.config.add_peer(
                node_id,
                peer_data['node_id'],
                peer_data['public_key']
            )

            self.log(f"Peer akzeptiert: {node_id}")
            del self.pending_auth[node_id]
            self.pending_auth_list.takeItem(self.pending_auth_list.row(current_item))
            self.auth_details_text.clear()

            QMessageBox.information(self, "Erfolg", f"Peer {node_id} akzeptiert!")

        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Fehler: {e}")
            self.log(f"FEHLER beim Akzeptieren: {e}")

    def reject_peer(self):
        """Peer ablehnen"""
        current_item = self.pending_auth_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warnung", "Bitte einen Peer auswählen!")
            return

        node_id = current_item.data(Qt.ItemDataRole.UserRole)

        self.log(f"Peer abgelehnt: {node_id}")
        del self.pending_auth[node_id]
        self.pending_auth_list.takeItem(self.pending_auth_list.row(current_item))
        self.auth_details_text.clear()

        QMessageBox.information(self, "Info", f"Peer {node_id} abgelehnt!")

    def update_ui(self):
        """UI periodisch updaten"""
        if self.node:
            self.update_node_info()
            self.update_peers_list()
            self.update_topics_list()

    def update_node_info(self):
        """Node-Informationen updaten"""
        if not self.node:
            self.node_info_text.setText("Node nicht aktiv")
            return

        try:
            info = f"""
Node ID: {self.node.node_id}
Peer ID: {self.node.host.get_id() if self.node.host else 'N/A'}

Public Key:
{self.node.crypto.get_public_key_pem()[:100]}...

Status: AKTIV
Angebotene Topics: {len(self.node.provided_topics)}
Abonnierte Topics: {len(self.node.subscribed_topics)}
"""
            self.node_info_text.setText(info)
        except Exception as e:
            self.log(f"Fehler beim Update: {e}")

    def update_peers_list(self):
        """Peer-Liste updaten"""
        if not self.node:
            return

        try:
            self.peers_list.clear()

            for node_id, peer_info in self.node.config.get_all_peers().items():
                item = QTreeWidgetItem()
                item.setText(0, node_id[:16] + "...")
                item.setText(1, peer_info.get('peer_id', 'N/A')[:16] + "...")
                item.setText(2, "Verbunden")
                self.peers_list.addTopLevelItem(item)

        except Exception as e:
            self.log(f"Fehler beim Peers Update: {e}")

    def update_topics_list(self):
        """Topic-Liste updaten"""
        if not self.node:
            return

        try:
            self.topics_tree.clear()

            # Angebotene Topics
            for topic in self.node.provided_topics:
                item = QTreeWidgetItem()
                item.setText(0, topic)
                item.setText(1, self.node.node_id[:16] + "...")
                item.setText(2, "Angeboten")
                item.setForeground(0, QColor("green"))
                self.topics_tree.addTopLevelItem(item)

            # Abonnierte Topics
            for topic in self.node.subscribed_topics:
                provider = asyncio.run_coroutine_threadsafe(
                    self.node.registry.get_provider(topic),
                    self.node_thread.loop
                ).result(timeout=1)

                item = QTreeWidgetItem()
                item.setText(0, topic)
                item.setText(1, provider[1][:16] + "..." if provider else "Unbekannt")
                item.setText(2, "Abonniert")
                item.setForeground(0, QColor("blue"))
                self.topics_tree.addTopLevelItem(item)

        except Exception as e:
            self.log(f"Fehler beim Topics Update: {e}")

    def log(self, message: str):
        """Log-Meldung"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"

        cursor = self.logs_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(log_line + "\n")
        self.logs_text.setTextCursor(cursor)


def main():
    app = QApplication(sys.argv)
    window = NodeGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
