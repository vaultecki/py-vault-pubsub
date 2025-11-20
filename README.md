# README.md

# libp2p PubSub Netzwerk mit GUI

Ein dezentrales Publish-Subscribe Netzwerk basierend auf libp2p mit einer grafischen Benutzeroberfläche. Nodes können sich gegenseitig entdecken, Topics anbieten und abonnieren, wobei alle Nachrichten kryptographisch signiert werden.

## Features

### Netzwerk-Features
- **libp2p Integration**: Verwendet QUIC und TCP für robuste Netzwerkkommunikation
- **GossipSub Protocol**: Effizientes Publish-Subscribe System
- **Dezentrales Topic-Registry**: Automatische Verwaltung von Topic-Providern
- **Automatisches Reconnecting**: Periodische Verbindungsversuche zu bekannten Peers

### Sicherheit
- **Ed25519 Signaturen**: Alle Nachrichten werden digital signiert
- **Peer-Authentifizierung**: Neue Nodes müssen vom Benutzer bestätigt werden
- **Public-Key-Infrastruktur**: Sichere Kommunikation zwischen bekannten Peers
- **Persistente Konfiguration**: Schlüssel und Peer-Informationen werden lokal gespeichert

### Logging & Monitoring
- **Message Logging**: Alle Nachrichten werden protokolliert mit Zeitstempel
- **Eindeutige Node IDs**: Jeder Node hat eine persistente UUID
- **Detaillierte Logs**: Nachverfolgung aller Netzwerkereignisse

### Benutzeroberfläche
- **Grafische GUI**: PyQt6-basierte Verwaltungsoberfläche
- **Live-Monitoring**: Echtzeit-Anzeige von Verbindungen und Topics
- **Peer-Management**: Akzeptieren/Ablehnen neuer Nodes
- **Topic-Management**: Einfaches Anbieten und Abonnieren von Topics

## Installation

### Anforderungen
- Python 3.9+
- pip

### Setup

1. **Repository klonen oder herunterladen**
```bash
cd libp2p-pubsub-network
```

2. **Dependencies installieren**
```bash
pip install -r requirements.txt
```

## Verwendung

### GUI-Modus (empfohlen)

```bash
python node_gui.py
```

Die GUI startet einen Node und bietet:
- **Node Info Tab**: Node ID, Status, bekannte Nodes, Subscriber-Statistiken
- **Verbundene Nodes Tab**: Alle via Discovery gefundenen Nodes (online/offline)
- **Topics Tab**: Angebotene Topics, abonnierte Topics, Pending Topics
- **Authentifizierung Tab**: Neue Peer-Authentifizierungsanfragen akzeptieren/ablehnen
- **Logs Tab**: Live Aktivitäten und Fehler

### Kommandozeilen-Modus

```python
import asyncio
from node import PubSubNode

async def main():
    # Node mit Custom Ports erstellen
    node = PubSubNode(
        port=10000,           # Network Server Port
        local_port=9000,      # Lokale Interface Port
        config_path="config.json"
    )
    
    # Node starten
    await node.start()
    
    # Topic anbieten
    await node.provide_topic("sensor_data")
    
    # Nachricht publishen
    async def publish_example():
        for i in range(10):
            await node.publish("sensor_data", f"Sensor {i}".encode())
            await asyncio.sleep(1)
    
    asyncio.create_task(publish_example())
    
    # Laufen lassen
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown...")

asyncio.run(main())
```

### Externe Programme mit lokaler UDP Schnittstelle

```python
import socket
import json

# Mit lokalem Node verbinden (Port 9000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Topic abonnieren
msg = {'cmd': 'subscribe', 'topic': 'sensor_data'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))
response = sock.recvfrom(1024)
print(response)

# Nachricht publishen
msg = {
    'cmd': 'publish',
    'topic': 'sensor_data',
    'payload': 'temperature: 22.5'
}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))

# Topics auflisten
msg = {'cmd': 'list_topics'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))
response, _ = sock.recvfrom(4096)
print(json.loads(response))

sock.close()
```

## Konfiguration

### config.json Struktur

```json
{
  "node_id": "550e8400-e29b-41d4-a716-446655440000",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "peers": {
    "peer_node_id_1": {
      "peer_id": "peer_node_id_1",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...",
      "timestamp": 1234567890.123
    }
  },
  "dht_bootstrap_peers": []
}
```

### Discovery Service

Die Discovery läuft automatisch:

1. **Multicast Announcements** (alle 5 Sekunden)
   - Sendet alle angebotenen Topics
   - Port: 224.0.0.1:5353
   - Fallback auf Unicast wenn Multicast nicht verfügbar

2. **Known Nodes**
   - Speichert discovered Nodes mit deren Info
   - IP, Port, Topics, Last Seen

3. **Topic Registry**
   - Automatisch aktualisiert wenn neue Topics announced werden
   - Pending Topics werden periodisch gesucht

### Network Ports

- **Network Server**: TCP Port (default: 10000)
  - Eingehende Node-zu-Node Connections
  - Verschlüsselte Kommunikation
  
- **Local Interface**: UDP localhost (default: 9000)
  - Externe Programme verbinden sich hier
  - Unverschlüsselt (nur localhost)
  
- **Discovery**: UDP Multicast (224.0.0.1:5353)
  - Node-Discovery
  - Signiert, nicht verschlüsselt

## Architektur

### Komponenten

#### ConfigManager
- Persistente Speicherung von Node-Einstellungen
- Verwaltung von Schlüsseln und Peer-Informationen
- Automatische Initialisierung bei erstem Start

#### CryptoManager
- Ed25519 Schlüsselgenerierung
- Message Signing & Verification
- AES-256-GCM Verschlüsselung/Entschlüsselung
- Session Key Derivation (PBKDF2)

#### DiscoveryService
- UDP Multicast für automatische Node-Discovery
- Periodische Node-Ankündigungen (alle 5s)
- Fallback auf Unicast wenn Multicast nicht verfügbar
- Automatische Registry Updates

#### NodeConnectionPool & NodeConnection
- TCP Connection Management
- Automatische Verbindungswiederverwendung
- Fehlerbehandlung und Reconnecting

#### NetworkServer
- TCP Server für eingehende Connections
- Asynchrone Request-Verarbeitung
- Multi-Client Support

#### MessageHandler
- Message Type Routing
- Payload Entschlüsselung
- Signaturverifikation
- Subscriber Management

#### DistributedTopicRegistry
- Dezentrale Topic-Provider Registry
- Thread-sichere Operationen
- Topic-zu-Provider Mapping

#### MessageLogger
- Chronologische Message Protokollierung
- JSON-Format mit Metadaten
- Verschlüsselungsstatus Tracking

#### LocalInterface
- UDP Server für lokale Programme
- JSON-basiertes Command Protocol
- Publish/Subscribe/List Commands

### Sicherheitsarchitektur

```
Authentifizierung:
  - Node ID + Ed25519 Keys (persistent in config.json)
  - New Peer Auth Request (unverschlüsselt für Bootstrap)
  - Admin Approval erforderlich

Verschlüsselung:
  - Peer Discovery: Signiert aber unverschlüsselt
  - Topic Messages: AES-256-GCM (verschlüsselt)
  - Registry Updates: AES-256-GCM (verschlüsselt)
  - Subscriptions: AES-256-GCM (verschlüsselt)
  - Peer Auth: Unverschlüsselt (vor Authentifizierung)

Kommunikation:
  - Localhost UDP: Externe Programme <-> Node
  - Network TCP: Node <-> Node (verschlüsselt)
  - Multicast UDP: Node Discovery
```

### Message Types

```
1 = Registry Update (msg_type=1) - Verschlüsselt
    Topic Announcement mit Provider Info
    
2 = Topic Message (msg_type=2) - Verschlüsselt
    User Data auf subscribed Topics
    
3 = Subscription (msg_type=3) - Verschlüsselt
    Subscribe/Unsubscribe Notifications
    
4 = Peer Auth (msg_type=4) - NICHT Verschlüsselt
    New Node Authentication Requests
```

## Beispiele

### Beispiel 1: Zwei Nodes im selben Netzwerk

```bash
# Terminal 1 - Node A
python -c "
import asyncio
from node import PubSubNode

async def main():
    node_a = PubSubNode(port=10000, local_port=9000, config_path='node_a.json')
    await node_a.start()
    await node_a.provide_topic('temperature')
    await node_a.provide_topic('humidity')
    print('Node A läuft mit Topics: temperature, humidity')
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
"

# Terminal 2 - Node B
python -c "
import asyncio
from node import PubSubNode

async def message_handler(topic, payload):
    print(f'Node B empfangen auf {topic}: {payload}')

async def main():
    node_b = PubSubNode(port=10001, local_port=9001, config_path='node_b.json')
    await node_b.start()
    await node_b.subscribe('temperature', callback=message_handler)
    print('Node B abonniert: temperature')
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
"

# Terminal 3 - Publisher
python -c "
import asyncio
from node import PubSubNode

async def main():
    node_a = PubSubNode(port=10000, config_path='node_a.json')
    await node_a.start()
    
    for i in range(5):
        await node_a.publish('temperature', f'22.{i}°C'.encode())
        await asyncio.sleep(1)

asyncio.run(main())
"
```

### Beispiel 2: Peer Authentifizierung

Neue Nodes senden Authentifizierungsanfragen:
```
[New Node Discovery Announcement]
    ↓
[Admin sieht in GUI: "Neue Authentifizierungsanfrage"]
    ↓
[Admin klickt "Akzeptieren"]
    ↓
[Node wird zu config.json hinzugefügt]
    ↓
[Verschlüsselte Kommunikation aktiviert]
```

### Beispiel 3: Message Flow mit Verschlüsselung

```
Node A: publish("sensor_data", b"25.5°C")
    ↓
1. Signiere mit ED25519 Private Key
    ↓
2. Ableiten Session Key mit Node B Public Key (PBKDF2)
    ↓
3. Verschlüssele mit AES-256-GCM
    ↓
4. Format: [node_id][signature][IV][Tag][Encrypted Payload]
    ↓
5. TCP zu Node B Port 10000
    ↓
Node B empfängt:
    ↓
1. Entschlüssele mit Session Key
    ↓
2. Verifiziere Signatur
    ↓
3. Rufe Callbacks auf
    ↓
4. Logge Nachricht (mit verified=true)
```

## Message Logging

Alle Nachrichten werden in `message_logs/` protokolliert:

```
message_logs/messages_20240115_143022.log
```

Jeder Eintrag enthält:
```json
{
  "timestamp": "2024-01-15T14:30:22.123456",
  "direction": "received",
  "topic": "sensor_data",
  "source_node_id": "550e8400-e29b-41d4-a716-446655440000",
  "payload_size": 45,
  "payload_hash": "abc123def456...",
  "signature": "abcdef0123456789...",
  "verified": true
}
```

**Interpretation:**
- `direction`: "sent" oder "received"
- `verified`: Signaturverifizierung erfolgreich
- `payload_hash`: SHA256 Hash der Daten (für Privacy)
- `source_node_id`: Absender Node ID

## Ports und Schnittstellen

- **libp2p QUIC**: UDP Port (konfigurierbar, default: 10000)
- **libp2p TCP**: TCP Port (Port + 1000, default: 11000)
- **Lokale Schnittstelle**: UDP localhost (konfigurierbar, default: 9000)

## Sicherheit im Detail

### Authentifizierung & Autorisierung

**New Peer Flow:**
```
1. Neuer Node sendet Multicast Ankündigung
2. Bestehender Node empfängt Ankündigung
3. GUI zeigt "Neue Authentifizierungsanfrage"
4. Admin prüft: Node ID + Public Key
5. Admin klickt "Akzeptieren" oder "Ablehnen"
6. Entscheidung wird in config.json gespeichert
```

### Verschlüsselung Details

**AES-256-GCM:**
- **Schlüssellänge**: 256 Bit (32 Bytes)
- **IV Länge**: 96 Bit (12 Bytes, zufällig)
- **Tag Länge**: 128 Bit (16 Bytes, Auth-Tag)
- **Mode**: Galois/Counter Mode (Authenticated Encryption)

**Session Key Derivation (PBKDF2):**
```
Input: Kombinierte Public Keys (Sender + Empfänger)
Salt: "node_session_salt" (konstant)
Iterations: 100.000
Hash: SHA256
Output: 32 Bytes Session Key
Cache: Pro Peer (Wiederverwendung)
```

### Signatur Details

**Ed25519:**
- **Algorithm**: Elliptic Curve Digital Signature Algorithm
- **Signature Size**: 64 Bytes
- **Deterministic**: Gleicher Input = Gleiche Signatur
- **Schnell**: Microsekunden für Signieren/Verifizieren

### Datenfluss Verschlüsselung

```
Unverschlüsselt:
  - Multicast Discovery Announcements (aber signiert)
  - Peer Auth Requests (msg_type=4)
  
Verschlüsselt + Signiert:
  - Registry Updates (msg_type=1)
  - Topic Messages (msg_type=2)
  - Subscriptions (msg_type=3)
```

## Erweiterungsmöglichkeiten

- **End-to-End Encryption**: Topic-spezifische Keys (zusätzlich zu Node-Keys)
- **Topic Permissions**: Role-based Access Control pro Topic
- **Presence Information**: Online/Offline Status der Subscriber
- **Web Dashboard**: Browser-basierte Alternative zur Desktop-GUI
- **Metrics/Monitoring**: Prometheus Exporter für Netzwerk-Stats
- **Message Routing**: Intelligentes Routing basierend auf Latenz
- **Cluster Support**: Mehrere Nodes auf einer Maschine
- **Backup/Sync**: Automatische Config-Synchronisierung zwischen Nodes
- **DBus Integration**: D-Bus Service für Linux Systemintegration
- **Message Persistence**: Optional: Nachrichten in DB speichern

## Lizenz

MIT

## Autor

libp2p PubSub Network Team

## Support

Für Probleme oder Fragen, bitte ein Issue erstellen oder die Logs überprüfen.