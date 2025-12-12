# **WAN TCP Tunneler via Libp2p**

A robust, private peer-to-peer TCP tunneler designed to connect distinct sites across a WAN without requiring port forwarding on the client or server sides. It utilizes a public Relay node to hole-punch through NATs and establish direct, encrypted TCP or QUIC connections.

## **Features**

* **NAT Traversal:** Uses Libp2p Hole Punching to bypass firewalls.  
* **Private Network:** Enforced via a Pre-Shared Key (PSK) (swarm.key).  
* **End-to-End Encryption:** Optional AES-GCM layer for application data privacy, protecting data even from the relay.  
* **Identity Persistence:** Saves node identities to disk to ensure stable connectivity across restarts.  
* **Zero-Config Discovery:** Uses Kademlia DHT Rendezvous to find peers by a cluster ID string.

## **Prerequisites**

1. **Go:** Install Go 1.20 or higher.  
2. **Swarm Key:** You must generate a swarm.key file and place it in the working directory of **every** node (Relay, Server, Client).

\# Generate the Swarm Key  
echo \-e "/key/swarm/psk/1.0.0/\\n/base16/\\n$(openssl rand \-hex 32)" \> swarm.key

## **Quick Start**

### **1\. Start the Relay (Public Server)**

Run this on a machine with a public IP.  
go run main.go \-mode relay \-port 4001

*Copy the Multiaddr string printed in the logs (e.g., /ip4/1.2.3.4/udp/4001/quic-v1/p2p/Qm...).*

### **2\. Start the Server (Target Site)**

Run this on the machine hosting the service you want to expose (e.g., a web server on port 80).  
go run main.go \\  
  \-mode server \\  
  \-target 127.0.0.1:80 \\  
  \-relay "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/Qm..."

### **3\. Start the Client (User Site)**

Run this on your laptop to access the remote service.  
go run main.go \\  
  \-mode client \\  
  \-target 127.0.0.1:9090 \\  
  \-relay "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/Qm..."

*Access the service via http://localhost:9090.*

## **Flag Reference**

| Flag | Default | Description |
| :---- | :---- | :---- |
| \-mode | client | The operational mode of the node: relay, server, or client. |
| \-target | 127.0.0.1:8080 | **Server Mode:** The local address:port to expose (forward traffic to). **Client Mode:** The local address:port to listen on (accept traffic from). |
| \-relay | "" | The Multiaddr of the Relay node. **Required** for Server and Client modes to bootstrap into the WAN. |
| \-secret | swarm.key | Path to the Private Network Key (PSK) file. Must match on all nodes. |
| \-port | 0 / 4001 | The specific UDP/TCP port to listen on. Defaults to 4001 for Relays and 0 (random ephemeral) for Clients/Servers. |
| \-identity | identity-\<mode\>.key | Path to the node's private identity key. If missing, a new one is generated and saved. |
| \-datakey | "" | Path to Hex-encoded 32-byte key for additional AES-GCM data encryption. |

## **Security: Generating the Data Key**

While Libp2p encrypts the transport layer (TLS 1.3/Noise), you can add an extra layer of application-side encryption (AES-GCM). This ensures that the Relay (or any compromised hop) cannot read the actual data payload, even if they inspect the stream.  
To use this feature, both the **Client** and **Server** must start with the same \-datakey.

### **How to generate a 32-byte Hex Key**

Run the following command in your terminal:
openssl rand -hex 32 > data.key

Output Example:  
a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809

### **Usage**

**Server:**  
go run main.go \-mode server \-relay "..." \-datakey data.key

**Client:**  
go run main.go \-mode client \-relay "..." \-datakey data.key

If the keys do not match, the connection will drop immediately upon the first data packet exchange due to GCM authentication failure.