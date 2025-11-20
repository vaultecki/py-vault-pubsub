import asyncio
import json
import logging
from typing import Dict, Set, Callable, List, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
import socket
import struct

from libp2p import await_ready
from libp2p.host.basic_host import BasicHost
from libp2p.network.stream.exceptions import StreamEOF
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.id import ID
from libp2p.crypto.secp256k1 import create_new_private_key
from libp2p.pubsub.pubsub import Pubsub
from libp2p.pubsub.floodsub import FloodSub
from libp2p.pubsub.gossipsub import GossipSub
from libp2p.transport.quic.transport import QuicTransport
from libp2p.transport.tcp.transport import TCPTransport
from multiaddr import Multiaddr
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Protocol IDs für libp2p
TOPIC_REGISTRY_PROTOCOL = "/topic-registry/1.0.0"
MESSAGE_PROTOCOL = "/pubsub-message/1.0.0"


@dataclass
class TopicInfo:
    """Informationen über einen angebotenen Topic"""
    name: str
    provider_peer_id: str
    timestamp: float


@dataclass
class NodeInfo:
    """Information über einen Node im Netzwerk"""
    peer_id: str
    topics: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=lambda: datetime.now().timestamp())


class DistributedTopicRegistry:
    """Verteilte Registry der verfügbaren Topics"""

    def __init__(self):
        self.registry: Dict[str, TopicInfo] = {}
        self.node_info: Dict[str, NodeInfo] = {}
        self.lock = asyncio.Lock()

    async def register_topic(self, topic: str, provider_peer_id: str):
        """Topic registrieren"""
        async with self.lock:
            self.registry[topic] = TopicInfo(
                name=topic,
                provider_peer_id=provider_peer_id,
                timestamp=datetime.now().timestamp()
            )

            # NodeInfo aktualisieren
            if provider_peer_id not in self.node_info:
                self.node_info[provider_peer_id] = NodeInfo(peer_id=provider_peer_id)

            if topic not in self.node_info[provider_peer_id].topics:
                self.node_info[provider_peer_id].topics.append(topic)

            logger.info(f"Topic registriert: {topic} von {provider_peer_id}")

    async def unregister_topic(self, topic: str):
        """Topic deregistrieren"""
        async with self.lock:
            if topic in self.registry:
                del self.registry[topic]
                logger.info(f"Topic deregistriert: {topic}")

    async def get_provider(self, topic: str) -> Optional[str]:
        """Provider für einen Topic finden"""
        async with self.lock:
            info = self.registry.get(topic)
            return info.provider_peer_id if info else None

    async def get_all_topics(self) -> Dict[str, str]:
        """Alle Topics und deren Provider"""
        async with self.lock:
            return {info.name: info.provider_peer_id
                    for info in self.registry.values()}

    async def get_topics_for_provider(self, provider_peer_id: str) -> List[str]:
        """Alle Topics eines Providers"""
        async with self.lock:
            return self.node_info.get(provider_peer_id, NodeInfo(peer_id=provider_peer_id)).topics


class LocalInterface:
    """Lokale Schnittstelle für externe Programme (UDP)"""

    def __init__(self, node, port: int = 9000):
        self.node = node
        self.port = port
        self.sock = None

    async def start(self):
        """UDP Server starten"""
        loop = asyncio.get_event_loop()
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
                data = await stream.read(4096)
                if not data:
                    break

                await self._process_message(data, peer_id)
        except StreamEOF:
            logger.info(f"Stream geschlossen von {peer_id}")
        except Exception as e:
            logger.error(f"Fehler beim Lesen vom Stream: {e}")
        finally:
            await stream.close()

    async def _process_message(self, data: bytes, peer_id: ID):
        """Nachricht verarbeiten"""
        try:
            # Format: [type:1][length:4][payload:variable]
            if len(data) < 5:
                return

            msg_type = data[0]
            length = struct.unpack('>I', data[1:5])[0]
            payload = data[5:5 + length]

            if msg_type == 1:  # Registry Update
                await self._handle_registry_update(payload)
            elif msg_type == 2:  # Topic Message
                await self._handle_topic_message(payload)
        except Exception as e:
            logger.error(f"Fehler beim Verarbeiten der Nachricht: {e}")

    async def _handle_registry_update(self, payload: bytes):
        """Registry-Update von anderem Node"""
        try:
            msg = json.loads(payload.decode('utf-8'))
            topic = msg.get('topic')
            peer_id = msg.get('peer_id')

            if topic and peer_id:
                await self.node.registry.register_topic(topic, peer_id)
        except Exception as e:
            logger.error(f"Fehler beim Registry Update: {e}")

    async def _handle_topic_message(self, payload: bytes):
        """Nachricht auf Topic empfangen"""
        try:
            # Format: [topic_len:2][topic:variable][data:variable]
            topic_len = struct.unpack('>H', payload[:2])[0]
            topic = payload[2:2 + topic_len].decode('utf-8')
            message_data = payload[2 + topic_len:]

            await self.node._deliver_message(topic, message_data)
        except Exception as e:
            logger.error(f"Fehler beim Topic Message: {e}")


class PubSubNode:
    """Hauptknoten mit echter libp2p Integration"""

    def __init__(self, port: int = 10000, local_port: int = 9000,
                 bootstrap_peers: List[str] = None):
        self.port = port
        self.local_port = local_port
        self.bootstrap_peers = bootstrap_peers or []

        self.host: Optional[BasicHost] = None
        self.pubsub: Optional[Pubsub] = None
        self.registry = DistributedTopicRegistry()
        self.local_interface = LocalInterface(self, local_port)

        self.provided_topics: Set[str] = set()
        self.subscribed_topics: Set[str] = set()
        self.message_callbacks: Dict[str, List[Callable]] = {}

        self.topic_search_interval = 5
        self.pending_topics: Set[str] = set()

        self.message_handler = MessageHandler(self)
        self.peer_connections: Dict[str, any] = {}

    async def start(self):
        """Node starten und initialisieren"""
        try:
            logger.info("Starte libp2p Node...")

            # Host mit QUIC Transport erstellen
            private_key = create_new_private_key("secp256k1")

            self.host = BasicHost(
                private_key=private_key,
                transports=[QuicTransport(), TCPTransport()],
                muxers=[],
                security_options=[],
                peerstore=None
            )

            await self.host.get_ready()

            # PubSub (GossipSub) initialisieren
            self.pubsub = Pubsub(
                host=self.host,
                router=GossipSub(
                    protocols=["/meshsub/1.0.0"]
                )
            )
            await self.pubsub.wait_until_ready()

            # Adressen hinzufügen
            quic_addr = Multiaddr(f"/ip4/127.0.0.1/udp/{self.port}/quic")
            tcp_addr = Multiaddr(f"/ip4/127.0.0.1/tcp/{self.port + 1000}")

            await self.host.listen(quic_addr)
            await self.host.listen(tcp_addr)

            peer_id = self.host.get_id()
            logger.info(f"Node gestartet. Peer ID: {peer_id}")
            logger.info(f"Listening auf:")
            for addr in self.host.get_addrs():
                logger.info(f"  {addr}")

            # Stream Handler registrieren
            self.host.set_stream_handler(TOPIC_REGISTRY_PROTOCOL, self.message_handler.handle_stream)
            self.host.set_stream_handler(MESSAGE_PROTOCOL, self.message_handler.handle_stream)

            # Lokale Schnittstelle starten
            await self.local_interface.start()

            # Bootstrap Peers verbinden
            for peer_addr in self.bootstrap_peers:
                asyncio.create_task(self._connect_peer(peer_addr))

            # Background Tasks starten
            asyncio.create_task(self._periodic_topic_search())
            asyncio.create_task(self._periodic_registry_broadcast())

            logger.info("Node vollständig initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Starten des Nodes: {e}")
            raise

    async def provide_topic(self, topic: str):
        """Einen Topic anbieten"""
        if topic in self.provided_topics:
            logger.warning(f"Topic {topic} wird bereits angeboten")
            return

        self.provided_topics.add(topic)
        peer_id = str(self.host.get_id())
        await self.registry.register_topic(topic, peer_id)

        # Im PubSub subscriben um Nachrichten zu erhalten
        self.pubsub.subscribe(topic, callback=self._pubsub_message_handler)

        logger.info(f"Biete Topic an: {topic}")

    async def subscribe(self, topic: str, callback: Callable = None):
        """Auf einen Topic subscriben"""
        if topic in self.subscribed_topics:
            if callback and topic in self.message_callbacks:
                self.message_callbacks[topic].append(callback)
            return

        provider = await self.registry.get_provider(topic)

        if provider is None:
            logger.info(f"Kein Provider für {topic} gefunden. Werde periodisch suchen.")
            self.pending_topics.add(topic)
        else:
            await self._do_subscribe(topic, provider)

        if callback:
            if topic not in self.message_callbacks:
                self.message_callbacks[topic] = []
            self.message_callbacks[topic].append(callback)

    async def _do_subscribe(self, topic: str, provider_peer_id: str):
        """Tatsächlich auf einen Topic subscriben"""
        if topic in self.subscribed_topics:
            return

        self.subscribed_topics.add(topic)

        # Im PubSub subscriben
        try:
            self.pubsub.subscribe(topic, callback=self._pubsub_message_handler)
            logger.info(f"Subscribiert auf {topic} vom Provider {provider_peer_id}")
        except Exception as e:
            logger.error(f"Fehler beim Subscribe auf {topic}: {e}")
            self.subscribed_topics.remove(topic)

    async def publish(self, topic: str, payload: bytes):
        """Nachricht auf Topic publishen"""
        if topic not in self.provided_topics:
            logger.warning(f"Topic {topic} nicht angeboten")
            return

        try:
            # Nachricht im PubSub publishen
            await self.pubsub.publish(topic, payload)
            logger.info(f"Publishe auf {topic}: {len(payload)} bytes")
        except Exception as e:
            logger.error(f"Fehler beim Publishen: {e}")

    def _pubsub_message_handler(self, message):
        """Handler für Nachrichten vom PubSub"""
        topic = message.topicIDs[0] if message.topicIDs else "unknown"
        payload = message.data
        asyncio.create_task(self._deliver_message(topic, payload))

    async def _deliver_message(self, topic: str, payload: bytes):
        """Nachricht an registrierte Callbacks delivern"""
        if topic in self.message_callbacks:
            for callback in self.message_callbacks[topic]:
                try:
                    await callback(topic, payload)
                except Exception as e:
                    logger.error(f"Fehler in Callback für {topic}: {e}")

    async def _connect_peer(self, peer_multiaddr: str):
        """Zu einem Bootstrap Peer verbinden"""
        try:
            maddr = Multiaddr(peer_multiaddr)
            info = await self.host.connect(maddr)
            logger.info(f"Mit Peer verbunden: {info}")
        except Exception as e:
            logger.error(f"Fehler beim Verbinden mit Peer {peer_multiaddr}: {e}")

    async def _periodic_registry_broadcast(self):
        """Registry periodisch an Peers broadcasten"""
        while True:
            await asyncio.sleep(10)

            try:
                if not self.provided_topics:
                    continue

                peer_id = str(self.host.get_id())

                for topic in self.provided_topics:
                    msg = {
                        'topic': topic,
                        'peer_id': peer_id
                    }
                    payload = json.dumps(msg).encode('utf-8')

                    # Über alle Peers broadcasten
                    for peer in self.host.get_network().connections:
                        try:
                            stream = await self.host.new_stream(
                                peer.remote_peer,
                                [TOPIC_REGISTRY_PROTOCOL]
                            )

                            # Nachricht mit Header senden
                            msg_type = 1  # Registry Update
                            data = struct.pack('>BI', msg_type, len(payload)) + payload
                            await stream.write(data)
                            await stream.close()
                        except Exception as e:
                            logger.debug(f"Fehler beim Registry Broadcast: {e}")

            except Exception as e:
                logger.error(f"Fehler in Registry Broadcast: {e}")

    async def _periodic_topic_search(self):
        """Periodisch nach neuen Providern suchen"""
        while True:
            await asyncio.sleep(self.topic_search_interval)

            if not self.pending_topics:
                continue

            logger.debug(f"Suche nach Providern für: {self.pending_topics}")

            topics_to_remove = set()
            for topic in self.pending_topics:
                provider = await self.registry.get_provider(topic)
                if provider:
                    await self._do_subscribe(topic, provider)
                    topics_to_remove.add(topic)

            self.pending_topics -= topics_to_remove


async def main():
    """Beispiel: Zwei Nodes die sich verbinden"""

    # Node 1 starten
    node1 = PubSubNode(port=10000, local_port=9000)
    await node1.start()
    await node1.provide_topic("sensor_data")

    # Node 2 starten (würde auf anderem Rechner laufen)
    node2 = PubSubNode(port=10001, local_port=9001)
    await node2.start()

    # Node 2 subscribiert auf Topic von Node 1
    async def message_callback(topic: str, payload: bytes):
        logger.info(f"Node2 empfangen auf {topic}: {payload[:50]}")

    await node2.subscribe("sensor_data", callback=message_callback)

    await asyncio.sleep(2)

    # Nachrichten publishen
    for i in range(5):
        await node1.publish("sensor_data", f"Sensor Wert {i}".encode())
        await asyncio.sleep(1)

    await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
