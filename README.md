# libp2p PubSub Netzwerk mit Verschlüsselung & Admin-Management

Ein dezentrales Publish-Subscribe Netzwerk mit vollständiger Verschlüsselung, digitalen Signaturen und grafischem Admin-Interface. Nodes können sich automatisch entdecken, Topics anbieten/abonnieren, und der Admin kann neue Peers genehmigen oder entfernen - Änderungen werden automatisch im gesamten Netzwerk verteilt.

## Features

### 🔍 **Dezentrales Discovery**
- UDP Multicast für automatische Node-Erkennung
- Periodische Ankündigungen alle 5 Sekunden
- Unicast Fallback wenn Multicast nicht verfügbar
- Automatische Registry-Updates

### 📡 **Publish-Subscribe System**
- Topics können von jedem Node angeboten werden
- Nodes subscriben nur wenn lokal jemand den Topic benötigt
- Effiziente Message-Distribution an Subscriber
- Support für Binär-Daten

### 🔐 **Sicherheit**
- **Authentifizierung**: Ed25519 digitale Signaturen
- **Verschlüsselung**: AES-256-GCM für Node-zu-Node Kommunikation
- **Session Keys**: PBKDF2-basierte Key Derivation
- **Peer Auth**: Neue Nodes müssen vom Admin genehmigt werden
- **Message Logging**: Alle Nachrichten werden protokolliert

### 👨‍💼 **Admin Management**
- **Peer Authentifizierung**: GUI-basiertes Akzeptieren/Ablehnen neuer Nodes
- **Peer Entfernung**: Nodes können aus dem Netzwerk entfernt werden
- **Netzwerk-Propagation**: Admin-Entscheidungen werden zu allen Nodes gesendet
- **Automatische Synchronisation**: Alle Nodes aktualisieren ihre config.json

### 🎛️ **Grafische GUI**
- Node Informationen und Status in Echtzeit
- Übersicht verbundener Nodes mit Discovery
- Topic Management (Anbieten/Abonnieren)
- Authentifizierungs-Queue mit Details
- Live-Logging aller Events

### 📊 **Lokale Schnittstelle**
- UDP-basierte Lokalschnittstelle für externe Programme
- JSON-basiertes Command Protocol
- Publish/Subscribe/List Operations

## Installation

### Anforderungen
- Python 3.9+
- pip

### Setup

```bash
# Repository klonen
cd libp2p-pubsub-network

# Dependencies installieren
pip install -r requirements.txt

# GUI starten
python node_gui.py
```

## Verwendung

### GUI-Modus (Empfohlen)

```bash
python node_gui.py
```

**Reiter:**
- **Node Info**: Node ID, Status, bekannte Nodes, Subscriber-Statistiken
- **Verbundene Nodes**: Alle via Discovery gefundenen Nodes
- **Topics**: Angebotene, abonnierte und pending Topics
- **Authentifizierung**: Neue Peer-Requests akzeptieren/ablehnen/entfernen
- **Logs**: Alle Netzwerk-Events in Echtzeit

### Kommandozeilen-Modus

```python
import asyncio
from node import PubSubNode

async def main():
    node = PubSubNode(port=10000, local_port=9000, config_path="config.json")
    await node.start()
    await node.provide_topic("sensor_data")
    
    # Nachrichten publishen
    for i in range(10):
        await node.publish("sensor_data", f"Wert {i}".encode())
        await asyncio.sleep(1)

asyncio.run(main())
```

### Externe Programme (UDP Localhost)

```python
import socket
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Topic abonnieren
msg = {'cmd': 'subscribe', 'topic': 'sensor_data'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))

# Nachricht publishen
msg = {'cmd': 'publish', 'topic': 'sensor_data', 'payload': '25.5°C'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))

# Topics auflisten
msg = {'cmd': 'list_topics'}
sock.sendto(json.dumps(msg).encode(), ('127.0.0.1', 9000))
response, _ = sock.recvfrom(4096)
print(json.loads(response))

sock.close()
```

## Netzwerk-Verwaltung

### Peer Authentifizierung (Admin-Workflow)

```
1. Neuer Node sendet Discovery-Ankündigung
   └─ Enthält: Node ID, Public Key, Topics

2. Bestehender Node empfängt Ankündigung
   └─ Zeigt in GUI: "Neue Authentifizierungsanfrage"

3. Admin prüft Details:
   └─ Node ID ✓
   └─ Public Key Fingerprint ✓

4. Admin klickt "Akzeptieren"
   └─ Lokal in config.json gespeichert
   └─ Broadcast an alle Nodes (msg_type=5)

5. Alle Nodes erhalten Update
   └─ Aktualisieren ihre config.json
   └─ Verschlüsselte Kommunikation möglich
```

### Peer Entfernung (Admin-Workflow)

```
1. Admin wählt Peer aus "Verbundene Nodes"
   └─ Zeigt Node ID, IP, Topics

2. Admin klickt "Peer entfernen"
   └─ Bestätigungsdialog

3. Entfernung wird broadcastet (msg_type=5)
   └─ An alle bekannten Nodes

4. Jeder Node löscht Peer:
   └─ Aus config.json
   └─ Aus config.peers Dictionary
   └─ Keine weitere Kommunikation

5. Logs zeigen:
   └─ Admin Node ID
   └─ Timestamp
   └─ Entfernte Node ID
```

## Architektur

### Komponenten

| Komponente | Funktion |
|-----------|----------|
| **ConfigManager** | Persistente Konfiguration (config.json) |
| **CryptoManager** | Ed25519 Signaturen + AES-256-GCM |
| **DiscoveryService** | UDP Multicast Node-Erkennung |
| **NodeConnectionPool** | TCP Connection Management |
| **NetworkServer** | TCP Server für eingehende Connections |
| **MessageHandler** | Message Routing & Verarbeitung |
| **LocalInterface** | UDP Schnittstelle für externe Programme |
| **MessageLogger** | JSON-basierte Message-Protokollierung |

### Message Types

```
Type 1: Registry Update (Verschlüsselt)
  └─ Topic Announcement mit Provider Info
  └─ Von: Node mit neuem Topic
  └─ An: Alle bekannten Nodes

Type 2: Topic Message (Verschlüsselt)
  └─ User Data auf subscribed Topics
  └─ Von: Topic Provider
  └─ An: Subscriber Nodes

Type 3: Subscription (Verschlüsselt)
  └─ Subscribe/Unsubscribe Notifications
  └─ Von: Subscriber Node
  └─ An: Provider Node

Type 4: Peer Auth (NICHT Verschlüsselt)
  └─ New Node Authentication Requests
  └─ Von: Neuer Node
  └─ An: Bestehende Nodes
  └─ Grund: Noch keine Public Keys bekannt

Type 5: Peer Update (NICHT Verschlüsselt)
  └─ Admin Add/Remove Decisions
  └─ Von: Admin Node
  └─ An: Alle Nodes
  └─ Grund: Vor Authentifizierung nötig
```

### Verschlüsselung Details

**AES-256-GCM:**
- Schlüssellänge: 256 Bit (32 Bytes)
- IV Länge: 96 Bit (12 Bytes, zufällig)
- Auth Tag: 128 Bit (16 Bytes)
- Mode: Galois/Counter Mode

**Session Key Derivation (PBKDF2):**
```
Input: Kombinierte Public Keys (Sender + Empfänger)
Salt: "node_session_salt"
Iterations: 100.000
Hash: SHA256
Output: 32 Bytes Session Key (gecacht pro Peer)
```

**Ed25519 Signaturen:**
- Deterministic (gleicher Input = gleiche Signatur)
- 64 Bytes Signatur-Größe
- Microsekundenbereich für Sign/Verify

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

### Network Ports

- **Network Server**: TCP Port (default: 10000)
  - Eingehende Node-zu-Node Connections
  - Verschlüsselte Kommunikation
  
- **Local Interface**: UDP localhost (default: 9000)
  - Externe Programme
  - Unverschlüsselt (nur localhost)
  
- **Discovery**: UDP Multicast (224.0.0.1:5353)
  - Node-Discovery
  - Signiert, nicht verschlüsselt

## Message Logging

Alle Nachrichten werden in `message_logs/messages_YYYYMMDD_HHMMSS.log` protokolliert:

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

## Beispiele

### Beispiel 1: Multi-Node Setup

**Terminal 1 - Node A:**
```bash
python -c "
import asyncio
from node import PubSubNode

async def main():
    node = PubSubNode(port=10000, local_port=9000, config_path='node_a.json')
    await node.start()
    await node.provide_topic('temperature')
    print('Node A läuft')
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
"
```

**Terminal 2 - Node B:**
```bash
python -c "
import asyncio
from node import PubSubNode

async def callback(topic, payload):
    print(f'Node B empfangen: {payload}')

async def main():
    node = PubSubNode(port=10001, local_port=9001, config_path='node_b.json')
    await node.start()
    await node.subscribe('temperature', callback=callback)
    print('Node B läuft')
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
"
```

**Terminal 3 - Publisher:**
```bash
python -c "
import asyncio
from node import PubSubNode

async def main():
    node = PubSubNode(port=10000, config_path='node_a.json')
    await node.start()
    
    for i in range(5):
        await node.publish('temperature', f'22.{i}°C'.encode())
        await asyncio.sleep(1)

asyncio.run(main())
"
```

### Beispiel 2: Admin-Funktionen

1. **Neue Node genehmigen:**
   - GUI öffnet sich mit Authentifizierungs-Request
   - Admin prüft Node ID + Public Key
   - Klick auf "Akzeptieren"
   - Automatisch zu allen Nodes verteilt

2. **Node entfernen:**
   - In "Verbundene Nodes" Tab Peer auswählen
   - Klick auf "Peer entfernen"
   - Bestätigung + Broadcast
   - Automatisch aus allen Configs gelöscht

## Troubleshooting

### Node startet nicht
```
Fehler: "Fehler beim Starten des Nodes"
Lösung:
  - Port bereits in Verwendung? → Andere Port in GUI
  - Firewall blockiert? → Firewall konfigurieren
  - Python < 3.9? → Min. Python 3.9 erforderlich
```

### Keine Verbindung zu anderen Nodes
```
Symptom: "Discovered Nodes = 0"
Lösung:
  - Multicast aktiviert? → ifconfig | grep MULTICAST
  - Andere Nodes im Subnetz? → Prüfen
  - Firewall blockiert UDP 5353? → Konfigurieren
  - Unterschiedliche Configs? → Ja, ist OK
```

### Verschlüsselung schlägt fehl
```
Fehler: "Entschlüsselung fehlgeschlagen"
Lösung:
  - Private Keys unterschiedlich? → OK
  - Public Keys stimmen? → Prüfen!
  - Nachricht signiert? → Logs prüfen
```

### Peer Auth bleibt unverschlüsselt
```
Grund: Neuer Peer hat noch keinen Public Key
Lösung: Nach Authentifizierung → Verschlüsselt
```

## Performance

- **Message Latenz**: < 50ms (lokales Netzwerk)
- **Encryption Overhead**: ~5-10% (AES-256-GCM)
- **Discovery Zeit**: 5-10 Sekunden (Multicast)
- **Throughput**: Begrenzt durch Netzwerk-Interface

## Sicherheitshinweise

⚠️ **Wichtig:**
- Private Keys NIE über Netzwerk senden
- config.json ist sensitiv → Dateirechte 600
- Multicast nur im lokalen Netzwerk sicher
- Peer Auth: Admin muss Public Key verifizieren
- Message Logs können Metadaten enthalten

## Erweiterungsmöglichkeiten

- [ ] End-to-End Encryption (Topic-spezifische Keys)
- [ ] Topic Permissions (Role-based Access Control)
- [ ] Presence Information (Online/Offline Status)
- [ ] Web Dashboard (Browser-Interface)
- [ ] Metrics Export (Prometheus)
- [ ] Message Persistence (Optional DB)
- [ ] DBus Integration (Linux Systemd)
- [ ] Cluster Support (Mehrere Nodes/Maschine)

## Lizenz

MIT

## Support

Für Issues:
1. Logs in `message_logs/` prüfen
2. Config in `.json` überprüfen
3. GitHub Issues erstellen
