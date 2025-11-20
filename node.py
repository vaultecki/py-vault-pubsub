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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import pbkdf2 as PBKDF2
from cryptography.hazmat.primitives import hashes
import os

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
        self.session_keys: Dict[str, bytes] = {}  # node_id -> shared_key
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

    def derive_session_key(self, peer_node_id: str, peer_public_key_pem: str) -> bytes:
        """Session Key mit Peer ableiten (ECDH-like)"""
        if peer_node_id in self.session_keys:
            return self.session_keys[peer_node_id]

        # Einfache Key Derivation: Hash von kombinierten Public Keys
        combined = (self.get_public_key_pem() + peer_public_key_pem).encode()

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'node_session_salt',
            iterations=100000,
            backend=default_backend()
        )

        session_key = kdf.derive(combined)
        self.session_keys[peer_node_id] = session_key

        logger.debug(f"Session Key mit {peer_node_id[:8]}... erstellt")
        return session_key

    def encrypt_message(self, peer_node_id: str, peer_public_key_pem: str, plaintext: bytes) -> bytes:
        """Nachricht mit AES-256-GCM verschlüsseln"""
        session_key = self.derive_session_key(peer_node_id, peer_public_key_pem)

        # IV generieren
        iv = os.urandom(12)

        # AES-256-GCM Cipher
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Format: [iv:12][tag:16][ciphertext:variable]
        return iv + encryptor.tag + ciphertext

    def decrypt_message(self, peer_node_id: str, peer_public_key_pem: str, encrypted: bytes) -> bytes:
        """Nachricht mit AES-256-GCM entschlüsseln"""
        try:
            session_key = self.derive_session_key(peer_node_id, peer_public_key_pem)

            # Extrahiere IV, Tag und Ciphertext
            iv = encrypted[:12]
            tag = encrypted[12:28]
            ciphertext = encrypted[28:]

            # AES-256-GCM Cipher
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            logger.error(f"Entschlüsselung fehlgeschlagen: {e}")
            raise


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
                'direction': direction,
                'topic': topic,
                'source_node_id': source_node_id,
                'payload_size': len(payload),
                'payload_hash': hashlib.sha256(payload).hexdigest(),
                'signature': signature[:32] + '...',
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
        self.subscribers: Dict[str, Set[str]] = {}  # topic -> set of node_ids

    async def handle_stream(self, stream):
        """Stream-Handler (wird implementiert wenn libp2p verwendet wird)"""
        logger.info("Stream empfangen")
        try:
            while True:
                try:
                    data = await asyncio.wait_for(stream.read(4096), timeout=10.0)
                    if not data:
                        break
                    await self._process_message(data)
                except asyncio.TimeoutError:
                    continue
        except Exception as e:
            logger.error(f"Fehler beim Lesen vom Stream: {e}")

    async def _process_message(self, data: bytes):
        """Nachricht verarbeiten (entschlüsseln und validieren)"""
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

            encrypted_payload = data[offset:]

            # Peer Info abrufen
            peer = self.node.config.get_peer(node_id)
            if not peer:
                # Peer Auth Requests sind nicht verschlüsselt
                if msg_type == 4:
                    await self._handle_peer_auth(encrypted_payload, node_id)
                # Peer Update ist auch unverschlüsselt (von bekannten Peers)
                elif msg_type == 5:
                    await self._handle_peer_update(encrypted_payload, node_id)
                else:
                    logger.warning(f"Unbekannter Node: {node_id}")
                return

            # Entschlüsseln (außer Peer Auth und Peer Updates)
            if msg_type == 4 or msg_type == 5:
                payload = encrypted_payload
            else:
                try:
                    payload = self.node.crypto.decrypt_message(
                        node_id,
                        peer['public_key'],
                        encrypted_payload
                    )
                except Exception as e:
                    logger.error(f"Fehler beim Entschlüsseln von {node_id}: {e}")
                    return

            # Signatur verifizieren
            if not self.node.crypto.verify_signature(peer['public_key'], payload, signature):
                logger.error(f"Signatur ungültig für Message von {node_id}")
                return

            if msg_type == 1:
                await self._handle_registry_update(payload, node_id, signature)
            elif msg_type == 2:
                await self._handle_topic_message(payload, node_id, signature)
            elif msg_type == 3:
                await self._handle_subscription(payload, node_id, signature)
            elif msg_type == 4:
                await self._handle_peer_auth(payload, node_id)
            elif msg_type == 5:
                await self._handle_peer_update(payload, node_id)
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

    async def _handle_subscription(self, payload: bytes, node_id: str, signature: bytes):
        """Subscription Request von Remote Node"""
        try:
            msg = json.loads(payload.decode('utf-8'))
            topic = msg.get('topic')
            action = msg.get('action')

            if action == 'subscribe':
                if topic not in self.subscribers:
                    self.subscribers[topic] = set()
                self.subscribers[topic].add(node_id)
                logger.info(f"Node {node_id[:8]}... hat sich auf {topic} subscribiert")
                logger.debug(f"Aktuelle Subscriber für {topic}: {len(self.subscribers.get(topic, set()))}")

            elif action == 'unsubscribe':
                if topic in self.subscribers:
                    self.subscribers[topic].discard(node_id)
                    logger.info(f"Node {node_id[:8]}... hat sich von {topic} abgemeldet")

        except Exception as e:
            logger.error(f"Fehler beim Subscription Handler: {e}")

    async def _handle_peer_update(self, payload: bytes, node_id: str):
        """Admin Peer Update (Add/Remove) vom Netzwerk"""
        try:
            msg = json.loads(payload.decode('utf-8'))
            action = msg.get('action')  # 'add' oder 'remove'
            target_node_id = msg.get('target_node_id')
            target_public_key = msg.get('target_public_key')
            admin_node_id = msg.get('admin_node_id')

            if action == 'add':
                logger.info(f"Admin {admin_node_id[:8]}... hat {target_node_id[:8]}... genehmigt")
                self.node.config.add_peer(target_node_id, target_node_id, target_public_key)
                logger.info(f"Node {target_node_id[:8]}... lokal akzeptiert")

            elif action == 'remove':
                logger.warning(f"Admin {admin_node_id[:8]}... hat {target_node_id[:8]}... entfernt")
                if 'peers' in self.node.config.config and target_node_id in self.node.config.config['peers']:
                    del self.node.config.config['peers'][target_node_id]
                    self.node.config.save()
                    logger.warning(f"Node {target_node_id[:8]}... lokal entfernt")

        except Exception as e:
            logger.error(f"Fehler beim Peer Update Handler: {e}")

    async def _handle_peer_auth(self, payload: bytes, node_id: str):
        """Neue Node-Authentifizierungsanfrage"""
        try:
            msg = json.loads(payload.decode('utf-8'))
            new_node_id = msg.get('node_id')
            public_key = msg.get('public_key')
            peer_info = msg.get('peer_info')

            logger.warning(f"Neue Node Authentifizierungsanfrage:")
            logger.warning(f"  Node ID: {new_node_id}")
            logger.warning(f"  Public Key: {public_key[:50]}...")

            response = await self._prompt_user_auth(new_node_id, public_key)

            if response:
                self.node.config.add_peer(new_node_id, str(new_node_id), public_key)
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


class DiscoveryService:
    """UDP Multicast Discovery Service"""

    def __init__(self, node, discovery_port: int = 5353):
        self.node = node
        self.discovery_port = discovery_port
        self.multicast_group = ('224.0.0.1', 5353)
        self.discovery_sock = None
        self.known_nodes: Dict[str, dict] = {}

    async def start(self):
        """Discovery Service starten"""
        self.discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.discovery_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            self.discovery_sock.bind(('', self.discovery_port))

            mreq = socket.inet_aton('224.0.0.1') + socket.inet_aton('0.0.0.0')
            self.discovery_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            logger.warning(f"Multicast nicht verfügbar: {e}. Nutze Unicast stattdessen.")

        self.discovery_sock.setblocking(False)

        asyncio.create_task(self._listen_for_discoveries())
        asyncio.create_task(self._announce_self())
        logger.info("Discovery Service gestartet")

    async def _announce_self(self):
        """Eigenen Node periodisch ankündigen"""
        while True:
            await asyncio.sleep(5)

            try:
                announcement = {
                    'type': 'announce',
                    'node_id': self.node.node_id,
                    'port': self.node.port,
                    'topics': list(self.node.provided_topics),
                    'timestamp': datetime.now().timestamp(),
                    'public_key': self.node.crypto.get_public_key_pem()
                }

                msg = json.dumps(announcement).encode('utf-8')
                signature = self.node.crypto.sign_message(msg)

                # Multicast Announcement
                try:
                    payload = struct.pack('>I', len(signature)) + signature + msg
                    self.discovery_sock.sendto(payload, self.multicast_group)
                except:
                    pass

                # Unicast an bekannte Nodes
                for node_info in self.known_nodes.values():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(payload, (node_info['ip'], node_info['port']))
                        sock.close()
                    except:
                        pass

                logger.debug(f"Ankündigung gesendet: {len(self.node.provided_topics)} Topics")

            except Exception as e:
                logger.error(f"Fehler bei Ankündigung: {e}")

    async def _listen_for_discoveries(self):
        """Auf Node Ankündigungen lauschen"""
        loop = asyncio.get_event_loop()

        while True:
            try:
                data, addr = await loop.sock_recvfrom(self.discovery_sock, 4096)
                await self._process_discovery(data, addr)
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Discovery Fehler: {e}")
                await asyncio.sleep(0.1)

    async def _process_discovery(self, data: bytes, addr):
        """Discovery Nachricht verarbeiten"""
        try:
            if len(data) < 4:
                return

            sig_len = struct.unpack('>I', data[:4])[0]
            if len(data) < 4 + sig_len:
                return

            signature = data[4:4 + sig_len]
            msg_data = data[4 + sig_len:]

            msg = json.loads(msg_data.decode('utf-8'))
            node_id = msg.get('node_id')

            if node_id == self.node.node_id:
                return  # Ignoriere eigene Ankündigungen

            # Signatur verifizieren
            public_key_pem = msg.get('public_key')
            if not self.node.crypto.verify_signature(public_key_pem, msg_data, signature):
                logger.warning(f"Ungültige Signatur von {node_id}")
                return

            # Node speichern
            self.known_nodes[node_id] = {
                'node_id': node_id,
                'ip': addr[0],
                'port': msg.get('port'),
                'topics': msg.get('topics', []),
                'last_seen': msg.get('timestamp'),
                'public_key': public_key_pem
            }

            logger.info(f"Node entdeckt: {node_id[:8]}... mit {len(msg.get('topics', []))} Topics")

            # Topics in Registry eintragen
            for topic in msg.get('topics', []):
                await self.node.registry.register_topic(topic, node_id, node_id)

            # Pending Topics prüfen
            await self.node._check_pending_topics()

        except Exception as e:
            logger.error(f"Fehler beim Discovery Processing: {e}")


class NodeConnectionPool:
    """Verwaltet Verbindungen zu anderen Nodes"""

    def __init__(self, node):
        self.node = node
        self.connections: Dict[str, 'NodeConnection'] = {}
        self.lock = asyncio.Lock()

    async def get_or_create_connection(self, node_id: str, node_info: dict) -> 'NodeConnection':
        """Verbindung zu Node erstellen oder wiederverwenden"""
        async with self.lock:
            if node_id not in self.connections:
                conn = NodeConnection(self.node, node_id, node_info)
                self.connections[node_id] = conn
                await conn.connect()
            return self.connections[node_id]

    async def send_to_node(self, node_id: str, msg_type: int, payload: bytes, node_info: dict):
        """Nachricht zu Node senden"""
        try:
            conn = await self.get_or_create_connection(node_id, node_info)
            await conn.send_message(msg_type, payload)
        except Exception as e:
            logger.error(f"Fehler beim Senden an {node_id}: {e}")


class NodeConnection:
    """Verbindung zu einem anderen Node"""

    def __init__(self, node, peer_node_id: str, peer_info: dict):
        self.node = node
        self.peer_node_id = peer_node_id
        self.peer_info = peer_info
        self.reader = None
        self.writer = None

    async def connect(self):
        """Zu Remote Node verbinden"""
        try:
            ip = self.peer_info.get('ip')
            port = self.peer_info.get('port', 10000)

            self.reader, self.writer = await asyncio.open_connection(ip, port)
            logger.info(f"Verbunden mit Node {self.peer_node_id[:8]}... auf {ip}:{port}")

            asyncio.create_task(self._listen())
        except Exception as e:
            logger.error(f"Fehler beim Verbinden zu {self.peer_node_id}: {e}")

    async def send_message(self, msg_type: int, payload: bytes):
        """Nachricht senden (verschlüsselt)"""
        if not self.writer:
            await self.connect()

        try:
            # Nachricht signieren
            signature = self.node.crypto.sign_message(payload)
            node_id_bytes = self.node.node_id.encode('utf-8')

            # Unverschlüsseltes Format für Signatur
            plain_msg = (struct.pack('>B', msg_type) +
                         struct.pack('>H', len(node_id_bytes)) + node_id_bytes +
                         struct.pack('>I', len(signature)) + signature +
                         payload)

            # Peer Public Key abrufen
            peer_info = self.node.config.get_peer(self.peer_node_id)
            if not peer_info:
                logger.warning(f"Peer {self.peer_node_id} nicht konfiguriert")
                return

            peer_public_key = peer_info['public_key']

            # Verschlüsseln (außer msg_type, node_id und Signatur)
            payload_to_encrypt = payload
            encrypted_payload = self.node.crypto.encrypt_message(
                self.peer_node_id,
                peer_public_key,
                payload_to_encrypt
            )

            # Finales Format: [unencrypted_header][encrypted_payload]
            encrypted_msg = (struct.pack('>B', msg_type) +
                             struct.pack('>H', len(node_id_bytes)) + node_id_bytes +
                             struct.pack('>I', len(signature)) + signature +
                             encrypted_payload)

            self.writer.write(encrypted_msg)
            await self.writer.drain()

            logger.debug(f"Verschlüsselte Nachricht an {self.peer_node_id[:8]}... gesendet")
        except Exception as e:
            logger.error(f"Fehler beim Nachrichtensenden: {e}")
            self.writer = None

    async def _listen(self):
        """Auf Nachrichten von Remote Node lauschen"""
        try:
            while True:
                data = await self.reader.readexactly(4096)
                if not data:
                    break
                await self.node.message_handler._process_message(data)
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.debug(f"Connection zu {self.peer_node_id} geschlossen: {e}")


class NetworkServer:
    """TCP Server für eingehende Verbindungen"""

    def __init__(self, node, port: int = 10000):
        self.node = node
        self.port = port
        self.server = None

    async def start(self):
        """Server starten"""
        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                '0.0.0.0',
                self.port
            )

            async with self.server:
                logger.info(f"Network Server auf Port {self.port} gestartet")
                await self.server.serve_forever()
        except Exception as e:
            logger.error(f"Fehler beim Starten des Network Servers: {e}")

    async def _handle_client(self, reader, writer):
        """Eingehende Client-Verbindung bearbeiten"""
        try:
            while True:
                data = await reader.readexactly(4096)
                if not data:
                    break
                await self.node.message_handler._process_message(data)
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.debug(f"Client Fehler: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


class PubSubNode:
    """Hauptknoten mit Publish-Subscribe Funktionalität"""

    def __init__(self, port: int = 10000, local_port: int = 9000,
                 config_path: str = "config.json"):
        self.port = port
        self.local_port = local_port

        self.config = ConfigManager(config_path)
        self.node_id = self.config.get_node_id()
        self.crypto = CryptoManager(self.config)
        self.message_logger = MessageLogger()

        self.registry = DistributedTopicRegistry()
        self.local_interface = LocalInterface(self, local_port)
        self.discovery_service = DiscoveryService(self)
        self.connection_pool = NodeConnectionPool(self)
        self.network_server = NetworkServer(self, port)

        self.provided_topics: Set[str] = set()
        self.subscribed_topics: Set[str] = set()
        self.message_callbacks: Dict[str, List[Callable]] = {}

        self.topic_search_interval = 5
        self.pending_topics: Set[str] = set()

        self.message_handler = MessageHandler(self)
        self.reconnect_attempts: Dict[str, int] = {}
        self.max_reconnect_attempts = 5

        logger.info(f"Node ID: {self.node_id}")

    async def start(self):
        """Node starten und initialisieren"""
        try:
            logger.info("Starte PubSub Node...")

            # Network Server starten
            asyncio.create_task(self.network_server.start())

            # Discovery Service starten
            await self.discovery_service.start()

            # Lokale Schnittstelle starten
            await self.local_interface.start()

            # Background Tasks
            asyncio.create_task(self._periodic_topic_search())
            asyncio.create_task(self._distribute_topics())

            logger.info("Node vollständig initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Starten des Nodes: {e}")
            raise

    async def provide_topic(self, topic: str):
        """Topic anbieten"""
        if topic in self.provided_topics:
            logger.warning(f"Topic {topic} wird bereits angeboten")
            return

        self.provided_topics.add(topic)
        await self.registry.register_topic(topic, self.node_id, self.node_id)

        # An alle bekannten Nodes verteilen
        await self._distribute_topic(topic)

        logger.info(f"Biete Topic an: {topic}")

    async def subscribe(self, topic: str, callback: Callable = None):
        """Auf Topic subscriben (lokal oder remote)"""
        # Callback registrieren (von lokalem Programm)
        if callback:
            if topic not in self.message_callbacks:
                self.message_callbacks[topic] = []
            self.message_callbacks[topic].append(callback)

        # Wenn bereits subscribiert, fertig
        if topic in self.subscribed_topics:
            return

        # Prüfe ob Topic lokal angeboten wird
        if topic in self.provided_topics:
            logger.info(f"Topic {topic} wird lokal angeboten")
            self.subscribed_topics.add(topic)
            return

        # Suche nach Remote Provider
        provider = await self.registry.get_provider(topic)

        if provider is None:
            logger.info(f"Kein Provider für {topic} gefunden. Werde periodisch suchen.")
            self.pending_topics.add(topic)
        else:
            await self._do_subscribe(topic, provider[1])

    async def _do_subscribe(self, topic: str, provider_node_id: str):
        """Remote Topic subscriben (nur wenn lokal jemand abonniert hat)"""
        if topic in self.subscribed_topics:
            return

        self.subscribed_topics.add(topic)
        logger.info(f"Subscribiert auf Remote-Topic {topic} vom Node {provider_node_id[:8]}...")

        # Benachrichtige Remote Node dass wir subscribiert haben
        await self._notify_subscription(topic, provider_node_id)

    async def publish(self, topic: str, payload: bytes):
        """Nachricht publishen"""
        if topic not in self.provided_topics:
            logger.warning(f"Topic {topic} nicht angeboten")
            return

        try:
            signature = self.crypto.sign_message(payload)

            # Format: [topic_len:2][topic:var][payload:var]
            msg_data = struct.pack('>H', len(topic)) + topic.encode() + payload

            await self.message_logger.log_message(
                'sent', topic, self.node_id, payload,
                signature.hex()[:64], True
            )

            # An alle Subscriber verteilen
            await self._distribute_message(topic, msg_data)

            logger.info(f"Publishe auf {topic}: {len(payload)} bytes")
        except Exception as e:
            logger.error(f"Fehler beim Publishen: {e}")

    async def _deliver_message(self, topic: str, payload: bytes):
        """Nachricht an Callbacks delivern"""
        if topic in self.message_callbacks:
            for callback in self.message_callbacks[topic]:
                try:
                    await callback(topic, payload)
                except Exception as e:
                    logger.error(f"Fehler in Callback für {topic}: {e}")

    async def _distribute_topic(self, topic: str):
        """Topic an alle bekannten Nodes verteilen"""
        payload = json.dumps({
            'topic': topic,
            'node_id': self.node_id,
            'port': self.port
        }).encode('utf-8')

        for node_id, node_info in self.discovery_service.known_nodes.items():
            try:
                await self.connection_pool.send_to_node(node_id, 1, payload, node_info)
            except:
                pass

    async def _distribute_message(self, topic: str, msg_data: bytes):
        """Nachricht an alle Subscriber verteilen"""
        for node_id, node_info in self.discovery_service.known_nodes.items():
            try:
                await self.connection_pool.send_to_node(node_id, 2, msg_data, node_info)
            except:
                pass

    async def _notify_subscription(self, topic: str, provider_node_id: str):
        """Benachrichtige Provider Node dass wir subscribiert haben"""
        payload = json.dumps({
            'topic': topic,
            'node_id': self.node_id,
            'port': self.port,
            'action': 'subscribe'
        }).encode('utf-8')

        if provider_node_id in self.discovery_service.known_nodes:
            node_info = self.discovery_service.known_nodes[provider_node_id]
            try:
                await self.connection_pool.send_to_node(provider_node_id, 3, payload, node_info)
                logger.info(f"Subscription Benachrichtigung an {provider_node_id[:8]}... gesendet")
            except Exception as e:
                logger.error(f"Fehler beim Senden der Subscription: {e}")

    async def _distribute_topics(self):
        """Periodisch Topics an Netzwerk verteilen"""
        while True:
            await asyncio.sleep(10)

            for topic in self.provided_topics:
                await self._distribute_topic(topic)

    async def _check_pending_topics(self):
        """Prüfe ob Pending Topics jetzt verfügbar sind"""
        topics_to_remove = set()
        for topic in self.pending_topics:
            provider = await self.registry.get_provider(topic)
            if provider:
                await self._do_subscribe(topic, provider[1])
                topics_to_remove.add(topic)

        self.pending_topics -= topics_to_remove

    async def _periodic_topic_search(self):
        """Periodisch nach neuen Providern suchen"""
        while True:
            await asyncio.sleep(self.topic_search_interval)
            await self._check_pending_topics()

    async def _periodic_reconnect(self):
        """Periodisch Reconnect versuchen"""
        while True:
            await asyncio.sleep(30)

            try:
                for node_id, peer_info in self.config.get_all_peers().items():
                    if node_id not in self.reconnect_attempts:
                        self.reconnect_attempts[node_id] = 0

                    if self.reconnect_attempts.get(node_id, 0) < self.max_reconnect_attempts:
                        logger.debug(f"Versuche Reconnect zu Node {node_id}")
            except Exception as e:
                logger.error(f"Fehler in Reconnect: {e}")

    @property
    def peer_connections(self):
        """Kompatibilität"""
        return {}


async def main():
    """Beispiel: Node starten"""

    node1 = PubSubNode(port=10000, local_port=9000, config_path="config_node1.json")
    await node1.start()
    await node1.provide_topic("sensor_data")

    logger.info(f"Node 1 gestartet - ID: {node1.node_id}")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown...")


if __name__ == "__main__":
    asyncio.run(main())
