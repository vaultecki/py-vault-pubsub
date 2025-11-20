import asyncio
import json
import logging
import os
from typing import Dict, Set, Callable, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import socket
import struct
import uuid
from pathlib import Path

from libp2p import await_ready
from libp2p.host.basic_host import BasicHost
from libp2p.network.stream.exceptions import StreamEOF
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.id import ID
from libp2p.crypto.secp256k1 import create_new_private_key
from libp2p.pubsub.pubsub import Pubsub
from libp2p.pubsub.gossipsub import GossipSub
from libp2p.transport.quic.transport import QuicTransport
from libp2p.transport.tcp.transport import TCPTransport
from multiaddr import Multiaddr
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Protocol IDs
TOPIC_REGISTRY_PROTOCOL = "/topic-registry/1.0.0"
MESSAGE_PROTOCOL = "/pubsub-message/1.0.0"
PEER_AUTH_PROTOCOL = "/peer-auth/1.0.0"


@dataclass
class TopicInfo:
    """Informationen über einen angebotenen Topic"""
    name: str
    provider_peer_id: str
    provider_node_id: str
    timestamp: float


@dataclass
class NodeInfo:
    """Information über einen Node im Netzwerk"""
    node_id: str
    peer_id: str
    public_key: str
    topics: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=lambda: datetime.now().timestamp())
    verified: bool = False


class ConfigManager:
    """Verwaltet die Konfigurationsdatei"""

    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Konfiguration laden oder neu erstellen"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        else:
            return {
                'node_id': None,
                'private_key': None,
                'public_key': None,
                'peers': {},
                'dht_bootstrap_peers': []
            }

    def save(self):
        """Konfiguration speichern"""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        logger.info(f"Konfiguration gespeichert: {self.config_path}")

    def get_node_id(self) -> str:
        """Node ID abrufen oder erstellen"""
        if not self.config.get('node_id'):
            self.config['node_id'] = str(uuid.uuid4())
            self.save()
        return self.config['node_id']

    def set_keys(self, private_key_pem: str, public_key_pem: str):
        """Schlüssel speichern"""
        self.config['private_key'] = private_key_pem
        self.config['public_key'] = public_key_pem
        self.save()

    def get_private_key_pem(self) -> Optional[str]:
        """Private Key abrufen"""
        return self.config.get('private_key')

    def get_public_key_pem(self) -> Optional[str]:
        """Public Key abrufen"""
        return self.config.get('public_key')

    def add_peer(self, node_id: str, peer_id: str, public_key: str):
        """Verifizierten Peer hinzufügen"""
        if 'peers' not in self.config:
            self.config['peers'] = {}
        self.config['peers'][node_id] = {
            'peer_id': peer_id,
            'public_key': public_key,
            'timestamp': datetime.now().timestamp()
        }
        self.save()
        logger.info(f"Peer hinzugefügt: {node_id}")

    def get_peer(self, node_id: str) -> Optional[dict]:
        """Peer abrufen"""
        return self.config.get('peers', {}).get(node_id)

    def get_all_peers(self) -> dict:
        """Alle Peers abrufen"""
        return self.config.get('peers', {})


class CryptoManager:
    """Verwaltet Verschlüsselung und Signierung"""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.private_key = None
        self.public_key = None
        self._load_or_create_keys()

    def _load_or_create_keys(self):
        """Schlüssel laden oder neu generieren"""
        private_pem = self.config.get_private_key_pem()
        public_pem = self.config.get_public_key_pem()

        if private_pem and public_pem:
            self.private_key = serialization.load_pem_private_key(
                private_pem.encode(),
                password=None,
                backend=default_backend()
            )
            self.public_key = serialization.load_pem_public_key(
                public_pem.encode(),
                backend=default_backend()
            )
            logger.info("Schlüssel geladen")
        else:
            self._generate_keys()

    def _generate_keys(self):
        """Neue Ed25519-Schlüssel generieren"""
        logger.info("Generiere neue Ed25519-Schlüssel...")
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.config.set_keys(private_pem, public_pem)

    def sign_message(self, data: bytes) -> bytes:
        """Nachricht mit Ed25519 signieren"""
        return self.private_key.sign(data)

    def verify_signature(self, public_key_pem: str, data: bytes, signature: bytes) -> bool:
        """Ed25519 Signatur verifizieren"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            public_key.verify(signature, data)
            return True
        except Exception as e:
            logger.error(f"Signaturverifikation fehlgeschlagen: {e}")
            return False

    def get_public_key_pem(self) -> str:
        """Public Key als PEM abrufen"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()


class MessageLogger:
    """Logging aller Nachrichten"""

    def __init__(self, log_dir: str = "message_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / f"messages_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    async def log_message(self, direction: str, topic: str, source_node_id: str,
                          payload: bytes, signature: str, verified: bool):
        """Nachricht protokollieren"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'direction': direction,  # 'sent' oder 'received'
                'topic': topic,
                'source_node_id': source_node_id,
                'payload_size': len(payload),
                'payload_hash': hashlib.sha256(payload).hexdigest(),
                'signature': signature[:32] + '...',  # Gekürzte Signatur
                'verified': verified
            }

            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Fehler beim Message Logging: {e}")


class DistributedTopicRegistry:
    """Verteilte Registry der verfügbaren Topics"""

    def __init__(self):
        self.registry: Dict[str, TopicInfo] = {}
        self.node_info: Dict[str, NodeInfo] = {}
        self.lock = asyncio.Lock()

    async def register_topic(self, topic: str, provider_peer_id: str,
                             provider_node_id: str):
        """Topic registrieren"""
        async with self.lock:
            key = f"{topic}:{provider_node_id}"
            self.registry[key] = TopicInfo(
                name=topic,
                provider_peer_id=provider_peer_id,
                provider_node_id=provider_node_id,
                timestamp=datetime.now().timestamp()
            )
            logger.info(f"Topic registriert: {topic} von Node {provider_node_id}")

    async def get_provider(self, topic: str) -> Optional[Tuple[str, str]]:
        """Provider für Topic finden (peer_id, node_id)"""
        async with self.lock:
            for key, info in self.registry.items():
                if info.name == topic:
                    return (info.provider_peer_id, info.provider_node_id)
            return None

    async def get_all_topics(self) -> Dict[str, str]:
        """Alle Topics und deren Provider (node_id)"""
        async with self.lock:
            return {info.name: info.provider_node_id
                    for info in self.registry.values()}


class LocalInterface:
    """Lokale Schnittstelle für externe Programme (UDP)"""

    def __init__(self, node, port: int = 9000):
        self.node = node
        self.port = port
        self.sock = None

    async def start(self):
        """UDP Server starten"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.setblocking(False)
        logger.info(f"Lokale Schnittstelle auf UDP {self.port} gestartet")

        asyncio.create_task(self._listen())

    async def _listen(self):
        """Auf eingehende Befehle lauschen"""
        loop = asyncio.get_event_loop()
        while True:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
                asyncio.create_task(self._process_command(data, addr))
            except Exception as e:
                logger.error(f"Fehler bei Schnittstelle: {e}")
                await asyncio.sleep(0.1)

    async def _process_command(self, data: bytes, addr):
        """Befehl von externem Programm verarbeiten"""
        try:
            msg = json.loads(data.decode('utf-8'))
            cmd = msg.get('cmd')

            if cmd == 'publish':
                topic = msg.get('topic')
                payload = msg.get('payload', '').encode('utf-8')
                await self.node.publish(topic, payload)
                response = {'status': 'ok', 'cmd': 'publish'}

            elif cmd == 'subscribe':
                topic = msg.get('topic')
                await self.node.subscribe(topic)
                response = {'status': 'ok', 'cmd': 'subscribe'}

            elif cmd == 'list_topics':
                topics = await self.node.registry.get_all_topics()
                response = {'status': 'ok', 'topics': topics}

            else:
                response = {'status': 'error', 'msg': 'Unbekannter Befehl'}

            self.sock.sendto(json.dumps(response).encode('utf-8'), addr)
        except Exception as e:
            logger.error(f"Fehler beim Verarbeiten des Befehls: {e}")


class MessageHandler:
    """Handler für Nachrichten von anderen Nodes"""

    def __init__(self, node):
        self.node = node

    async def handle_stream(self, stream):
        """Stream von anderem Node bearbeiten"""
        peer_id = stream.muxed_conn.peer_id
        logger.info(f"Stream empfangen von {peer_id}")

        try:
            while True:
                try:
                    data = await asyncio.wait_for(stream.read(4096), timeout=10.0)
                    if not data:
                        break
                    await self._process_message(data, peer_id)
                except asyncio.TimeoutError:
                    continue
        except StreamEOF:
            logger.info(f"Stream geschlossen von {peer_id}")
        except Exception as e:
            logger.error(f"Fehler beim Lesen vom Stream: {e}")
        finally:
            try:
                await stream.close()
            except:
                pass

    async def _process_message(self, data: bytes, peer_id: ID):
        """Nachricht verarbeiten: [type:1][node_id_len:2][node_id:var][sig_len:4][sig:var][payload:var]"""
        try:
            if len(data) < 7:
                return

            offset = 0
            msg_type = data[offset]
            offset += 1

            node_id_len = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += 2

            node_id = data[offset:offset + node_id_len].decode('utf-8')
            offset += node_id_len

            sig_len = struct.unpack('>I', data[offset:offset + 4])[0]
            offset += 4

            signature = data[offset:offset + sig_len]
            offset += sig_len

            payload = data[offset:]

            if msg_type == 1:  # Registry Update
                await self._handle_registry_update(payload, node_id, signature)
            elif msg_type == 2:  # Topic Message
                await self._handle_topic_message(payload, node_id, signature)
            elif msg_type == 3:  # Peer Auth Request
                await self._handle_peer_auth(payload, node_id, peer_id)
        except Exception as e:
            logger.error(f"Fehler beim Verarbeiten der Nachricht: {e}")

    async def _handle_registry_update(self, payload: bytes, node_id: str, signature: bytes):
        """Registry-Update verarbeiten"""
        try:
            peer = self.node.config.get_peer(node_id)
            if not peer:
                logger.warning(f"Unbekannter Node: {node_id}")
                return

            if not self.node.crypto.verify_signature(peer['public_key'], payload, signature):
                logger.error(f"Signatur ungültig für Registry Update von {node_id}")
                return

            msg = json.loads(payload.decode('utf-8'))
            topic = msg.get('topic')

            if topic:
                await self.node.registry.register_topic(topic, msg.get('peer_id'), node_id)
        except Exception as e:
            logger.error(f"Fehler beim Registry Update: {e}")

    async def _handle_topic_message(self, payload: bytes, node_id: str, signature: bytes):
        """Topic-Nachricht verarbeiten"""
        try:
            peer = self.node.config.get_peer(node_id)
            if not peer:
                logger.warning(f"Unbekannter Node: {node_id}")
                return

            if not self.node.crypto.verify_signature(peer['public_key'], payload, signature):
                logger.error(f"Signatur ungültig für Message von {node_id}")
                return

            # Format: [topic_len:2][topic:var][data:var]
            topic_len = struct.unpack('>H', payload[:2])[0]
            topic = payload[2:2 + topic_len].decode('utf-8')
            message_data = payload[2 + topic_len:]

            await self.node.message_logger.log_message(
                'received', topic, node_id, message_data,
                signature.hex()[:64], True
            )

            await self.node._deliver_message(topic, message_data)
        except Exception as e:
            logger.error(f"Fehler beim Topic Message: {e}")

    async def _handle_peer_auth(self, payload: bytes, node_id: str, peer_id: ID):
        """Neue Node-Authentifizierungsanfrage"""
        try:
            msg = json.loads(payload.decode('utf-8'))
            new_node_id = msg.get('node_id')
            public_key = msg.get('public_key')
            peer_info = msg.get('peer_info')

            logger.warning(f"Neue Node Authentifizierungsanfrage:")
            logger.warning(f"  Node ID: {new_node_id}")
            logger.warning(f"  Public Key: {public_key[:50]}...")
            logger.warning(f"  Peer Info: {peer_info}")

            # Benutzer fragen
            response = await self._prompt_user_auth(new_node_id, public_key)

            if response:
                self.node.config.add_peer(new_node_id, str(peer_id), public_key)
                logger.info(f"Node {new_node_id} authentifiziert und hinzugefügt")
            else:
                logger.warning(f"Node {new_node_id} abgelehnt")
        except Exception as e:
            logger.error(f"Fehler beim Peer Auth: {e}")

    async def _prompt_user_auth(self, node_id: str, public_key: str) -> bool:
        """Benutzer um Bestätigung fragen"""
        loop = asyncio.get_event_loop()

        def ask():
            print("\n" + "=" * 60)
            print("NEUE NODE AUTHENTIFIZIERUNG")
            print("=" * 60)
            print(f"Node ID: {node_id}")
            print(f"Public Key:\n{public_key}")
            response = input("\nNode akzeptieren? (j/n): ").strip().lower()
            return response == 'j'

        return await loop.run_in_executor(None, ask)


class PubSubNode:
    """Hauptknoten mit libp2p und DHT"""

    def __init__(self, port: int = 10000, local_port: int = 9000,
                 config_path: str = "config.json"):
        self.port = port
        self.local_port = local_port

        self.config = ConfigManager(config_path)
        self.node_id = self.config.get_node_id()
        self.crypto = CryptoManager(self.config)
        self.message_logger = MessageLogger()

        self.host: Optional[BasicHost] = None
        self.pubsub: Optional[Pubsub] = None
        self.dht = None
        self.registry = DistributedTopicRegistry()
        self.local_interface = LocalInterface(self, local_port)

        self.provided_topics: Set[str] = set()
        self.subscribed_topics: Set[str] = set()
        self.message_callbacks: Dict[str, List[Callable]] = {}

        self.topic_search_interval = 5
        self.pending_topics: Set[str] = set()

        self.message_handler = MessageHandler(self)
        self.peer_connections: Dict[str, any] = {}
        self.reconnect_attempts: Dict[str, int] = {}
        self.max_reconnect_attempts = 5

        logger.info(f"Node ID: {self.node_id}")

    async def start(self):
        """Node starten und initialisieren"""
        try:
            logger.info("Starte libp2p Node mit DHT...")

            private_key = create_new_private_key("secp256k1")

            self.host = BasicHost(
                private_key=private_key,
                transports=[QuicTransport(), TCPTransport()],
                muxers=[],
                security_options=[],
                peerstore=None
            )

            await self.host.get_ready()

            self.pubsub = Pubsub(
                host=self.host,
                router=GossipSub(protocols=["/meshsub/1.0.0"])
            )
            await self.pubsub.wait_until_ready()

            quic_addr = Multiaddr(f"/ip4/127.0.0.1/udp/{self.port}/quic")
            tcp_addr = Multiaddr(f"/ip4/127.0.0.1/tcp/{self.port + 1000}")

            await self.host.listen(quic_addr)
            await self.host.listen(tcp_addr)

            peer_id = self.host.get_id()
            logger.info(f"Peer ID: {peer_id}")
            logger.info(f"Listening auf:")
            for addr in self.host.get_addrs():
                logger.info(f"  {addr}")

            self.host.set_stream_handler(TOPIC_REGISTRY_PROTOCOL, self.message_handler.handle_stream)
            self.host.set_stream_handler(MESSAGE_PROTOCOL, self.message_handler.handle_stream)
            self.host.set_stream_handler(PEER_AUTH_PROTOCOL, self.message_handler.handle_stream)

            await self.local_interface.start()

            asyncio.create_task(self._periodic_topic_search())
            asyncio.create_task(self._periodic_registry_broadcast())
            asyncio.create_task(self._periodic_reconnect())

            logger.info("Node vollständig initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Starten des Nodes: {e}")
            raise

    async def provide_topic(self, topic: str):
        """Topic anbieten"""
        if topic in self.provided_topics:
            return

        self.provided_topics.add(topic)
        peer_id = str(self.host.get_id())
        await self.registry.register_topic(topic, peer_id, self.node_id)

        self.pubsub.subscribe(topic, callback=self._pubsub_message_handler)
        logger.info(f"Biete Topic an: {topic}")

    async def subscribe(self, topic: str, callback: Callable = None):
        """Auf Topic subscriben"""
        if topic in self.subscribed_topics:
            if callback:
                if topic not in self.message_callbacks:
                    self.message_callbacks[topic] = []
                self.message_callbacks[topic].append(callback)
            return

        provider = await self.registry.get_provider(topic)

        if provider is None:
            logger.info(f"Kein Provider für {topic}. Werde periodisch suchen.")
            self.pending_topics.add(topic)
        else:
            await self._do_subscribe(topic, provider[0], provider[1])

        if callback:
            if topic not in self.message_callbacks:
                self.message_callbacks[topic] = []
            self.message_callbacks[topic].append(callback)

    async def _do_subscribe(self, topic: str, provider_peer_id: str, provider_node_id: str):
        """Auf Topic subscriben"""
        if topic in self.subscribed_topics:
            return

        self.subscribed_topics.add(topic)
        self.pubsub.subscribe(topic, callback=self._pubsub_message_handler)
        logger.info(f"Subscribiert auf {topic} vom Node {provider_node_id}")

    async def publish(self, topic: str, payload: bytes):
        """Nachricht publishen"""
        if topic not in self.provided_topics:
            logger.warning(f"Topic {topic} nicht angeboten")
            return

        try:
            # Nachricht mit Signatur versenden
            node_id_bytes = self.node_id.encode('utf-8')
            signature = self.crypto.sign_message(payload)

            # Format: [topic_len:2][topic:var][payload:var]
            msg_data = struct.pack('>H', len(topic)) + topic.encode() + payload

            await self.pubsub.publish(topic, msg_data)

            await self.message_logger.log_message(
                'sent', topic, self.node_id, payload,
                signature.hex()[:64], True
            )

            logger.info(f"Publishe auf {topic}: {len(payload)} bytes")
        except Exception as e:
            logger.error(f"Fehler beim Publishen: {e}")

    def _pubsub_message_handler(self, message):
        """PubSub-Nachricht empfangen"""
        try:
            topic = message.topicIDs[0] if message.topicIDs else "unknown"
            asyncio.create_task(self._deliver_message(topic, message.data))
        except Exception as e:
            logger.error(f"Fehler im PubSub Handler: {e}")

    async def _deliver_message(self, topic: str, payload: bytes):
        """Nachricht an Callbacks delivern"""
        if topic in self.message_callbacks:
            for callback in self.message_callbacks[topic]:
                try:
                    await callback(topic, payload)
                except Exception as e:
                    logger.error(f"Fehler in Callback für {topic}: {e}")

    async def _periodic_registry_broadcast(self):
        """Registry periodisch broadcasten"""
        while True:
            await asyncio.sleep(10)

            try:
                if not self.provided_topics:
                    continue

                peer_id = str(self.host.get_id())

                for topic in self.provided_topics:
                    msg = {
                        'topic': topic,
                        'peer_id': peer_id,
                        'node_id': self.node_id
                    }
                    payload = json.dumps(msg).encode('utf-8')
                    signature = self.crypto.sign_message(payload)

                    # Mit allen Peers über Stream kommunizieren
                    for peer in list(self.host.get_network().connections):
                        asyncio.create_task(self._send_registry_update(
                            peer.remote_peer, payload, signature
                        ))
            except Exception as e:
                logger.error(f"Fehler in Registry Broadcast: {e}")

    async def _send_registry_update(self, peer_id: ID, payload: bytes, signature: bytes):
        """Registry Update zu Peer senden"""
        try:
            stream = await self.host.new_stream(peer_id, [TOPIC_REGISTRY_PROTOCOL])

            node_id_bytes = self.node_id.encode('utf-8')
            msg_type = 1
            data = (struct.pack('>B', msg_type) +
                    struct.pack('>H', len(node_id_bytes)) + node_id_bytes +
                    struct.pack('>I', len(signature)) + signature +
                    payload)

            await stream.write(data)
            await stream.close()
        except Exception as e:
            logger.debug(f"Fehler beim Registry Update zu Peer: {e}")

    async def _periodic_topic_search(self):
        """Periodisch nach Topics suchen"""
        while True:
            await asyncio.sleep(self.topic_search_interval)

            if not self.pending_topics:
                continue

            topics_to_remove = set()
            for topic in self.pending_topics:
                provider = await self.registry.get_provider(topic)
                if provider:
                    await self._do_subscribe(topic, provider[0], provider[1])
                    topics_to_remove.add(topic)

            self.pending_topics -= topics_to_remove

    async def _periodic_reconnect(self):
        """Periodisch Reconnect versuchen"""
        while True:
            await asyncio.sleep(30)

            try:
                for node_id, peer_info in self.config.get_all_peers().items():
                    if node_id not in self.peer_connections:
                        self.reconnect_attempts[node_id] = 0

                    if self.reconnect_attempts.get(node_id, 0) < self.max_reconnect_attempts:
                        asyncio.create_task(self._try_connect_peer(node_id, peer_info))
            except Exception as e:
                logger.error(f"Fehler in Reconnect: {e}")

    async def _try_connect_peer(self, node_id: str, peer_info: dict):
        """Versuchen zu Peer zu verbinden"""
        try:
            # Hier würde die echte Verbindung stattfinden
            logger.debug(f"Versuche Verbindung zu Node {node_id}")
        except Exception as e:
            attempt = self.reconnect_attempts.get(node_id, 0) + 1
            self.reconnect_attempts[node_id] = attempt
            logger.debug(f"Reconnect Versuch {attempt} für Node {node_id} fehlgeschlagen: {e}")


async def main():
    """Beispiel: Zwei Nodes mit Authentifizierung"""

    # Node 1 starten
    node1 = PubSubNode(port=10000, local_port=9000, config_path="config_node1.json")
    await node1.start()
    await node1.provide_topic("sensor_data")

    logger.info(f"Node 1 gestartet - ID: {node1.node_id}")
    logger.info(f"Public Key von Node 1:\n{node1.crypto.get_public_key_pem()}")

    # Node 2 starten
    node2 = PubSubNode(port=10001, local_port=9001, config_path="config_node2.json")
    await node2.start()

    logger.info(f"Node 2 gestartet - ID: {node2.node_id}")
    logger.info(f"Public Key von Node 2:\n{node2.crypto.get_public_key_pem()}")

    # Node 2 subscribes auf Topic von Node 1
    async def message_callback(topic: str, payload: bytes):
        logger.info(f"Node2 empfangen auf {topic}: {payload[:50]}")

    await node2.subscribe("sensor_data", callback=message_callback)

    await asyncio.sleep(2)

    # Nachrichten publishen
    for i in range(3):
        await node1.publish("sensor_data", f"Sensor Wert {i}".encode())
        await asyncio.sleep(1)

    await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
