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
- Python 3.8+
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
python gui.py
```

Dies startet die grafische Benutzeroberfläche. Von dort aus kannst du:
- Den Node starten/stoppen
- Port und Konfigurationsdatei einstellen
- Topics anbieten und abonnieren
- Verbundene Nodes verwalten
- Neue Peers authentifizieren

### Kommandozeilen-Modus

```python
import asyncio
from libp2p_pubsub_network import PubSubNode

async def main():
    # Node erstellen
    node = PubSubNode(port=10000, local_port=9000)
    
    # Node starten
    await node.start()
    
    # Topic anbieten
    await node.provide_topic("sensor_data")
    
    # Nachrichten publishen
    await node.publish("sensor_data", b"Test message")
    
    # Auf Events warten
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass

asyncio.run(main())
```

## Konfiguration

### config.json Struktur

```json
{
  "node_id": "550e8400-e29b-41d4-a716-446655440000",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "peers": {
    "node_id_1": {
      "peer_id": "QmXxxx...",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...",
      "timestamp": 1234567890.123
    }
  },
  "dht_bootstrap_peers": []
}
```

## Architektur

### Komponenten

#### ConfigManager
- Persistente Speicherung von Node-Einstellungen
- Verwaltung von Schlüsseln und Peer-Informationen
- Automatische Initialisierung bei erstem Start

#### CryptoManager
- Ed25519 Schlüsselgenerierung
- Nachrichtensignierung
- Signaturverifikation

#### DistributedTopicRegistry
- Dezentrale Verwaltung von Topic-Providern
- Automatische Registry-Updates zwischen Nodes
- Topic-Suche und Discovery

#### MessageHandler
- Verarbeitung eingehender Nachrichten
- Signaturverifikation
- Peer-Authentifizierungsanfragen

#### PubSubNode
- Zentrale Node-Klasse
- libp2p Host Management
- GossipSub Integration
- Automatisches Reconnecting

#### LocalInterface
- UDP-basierte lokale Schnittstelle
- Externe Programme können sich verbinden
- JSON-basiertes Command Protocol

#### MessageLogger
- Protokollierung aller Nachrichten
- Zeitstempel und Metadaten
- Separate Log-Dateien pro Sitzung

### Kommunikationsprotokolle

#### Topic-Registry-Protokoll (`/topic-registry/1.0.0`)
Nodes teilen ihre verfügbaren Topics mit anderen Nodes.

**Format:**
```
[type:1][node_id_len:2][node_id:var][sig_len:4][signature:var][payload:var]
```

#### Message-Protokoll (`/pubsub-message/1.0.0`)
Nachrichten zwischen Nodes über Streams.

**Format:**
```
[type:1][node_id_len:2][node_id:var][sig_len:4][signature:var][topic_len:2][topic:var][data:var]
```

#### Peer-Auth-Protokoll (`/peer-auth/1.0.0`)
Authentifizierungsanfragen neuer Nodes.

## Beispiele

### Beispiel 1: Zwei Nodes verbinden

```python
import asyncio
from libp2p_pubsub_network import PubSubNode

async def main():
    # Node 1: Bietet Sensor-Daten an
    node1 = PubSubNode(port=10000, local_port=9000, config_path="node1.json")
    await node1.start()
    await node1.provide_topic("sensors/temperature")
    
    # Node 2: Abonniert Sensor-Daten
    node2 = PubSubNode(port=10001, local_port=9001, config_path="node2.json")
    await node2.start()
    
    async def on_temperature(topic: str, payload: bytes):
        print(f"Temperatur empfangen: {payload}")
    
    await node2.subscribe("sensors/temperature", callback=on_temperature)
    
    # Daten publishen
    await node1.publish("sensors/temperature", b"25.5°C")

asyncio.run(main())
```

### Beispiel 2: Externe Programme verbinden (UDP)

```python
import socket
import json

# Mit lokalem Node verbinden
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Topic abonnieren
msg = {
    'cmd': 'subscribe',
    'topic': 'sensor_data'
}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))

# Daten publishen
msg = {
    'cmd': 'publish',
    'topic': 'sensor_data',
    'payload': 'sensor_value_123'
}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))

# Topics auflisten
msg = {'cmd': 'list_topics'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))
response, _ = sock.recvfrom(4096)
print(response.decode())

sock.close()
```

## Message Logging

Alle Nachrichten werden in `message_logs/` protokolliert:

```
message_logs/messages_20240115_143022.log
```

Jeder Eintrag enthält:
- Zeitstempel
- Richtung (sent/received)
- Topic-Name
- Payload-Größe und Hash
- Signatur (gekürzt)
- Verifikationsstatus

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

## Ports und Schnittstellen

- **libp2p QUIC**: UDP Port (konfigurierbar, default: 10000)
- **libp2p TCP**: TCP Port (Port + 1000, default: 11000)
- **Lokale Schnittstelle**: UDP localhost (konfigurierbar, default: 9000)

## Troubleshooting

### Node startet nicht
- Überprüfe, ob die Ports verfügbar sind
- Überprüfe die Firewall-Einstellungen
- Schau die Logs an: `message_logs/`

### Keine Verbindung zu anderen Nodes
- Stelle sicher, dass beide Nodes mit gleichen Ports erreichbar sind
- Überprüfe die Netzwerkverbindung
- Prüfe auf Firewall-Blockierung

### Peer-Authentifizierung schlägt fehl
- Überprüfe, dass die Public Keys korrekt sind
- Stelle sicher, dass der Peer bestätigt wurde
- Schau in die config.json um zu sehen ob der Peer gespeichert ist

## Erweiterungsmöglichkeiten

- DHT-Integration für besseres Discovery
- DBus-Unterstützung für Linux
- MQTT-Bridge für IoT-Kompatibilität
- Web-Interface als Alternative zur Desktop-GUI
- Message Encryption (zusätzlich zur Signatur)
- Automatische Backup-Verwaltung

## Lizenz

MIT

## Autor

libp2p PubSub Network Team

## Support

Für Probleme oder Fragen, bitte ein Issue erstellen oder die Logs überprüfen.