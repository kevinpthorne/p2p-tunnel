package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// Configuration Constants
const (
	TunnelProtocol = "/private-tunnel/1.0.0"
	RendezvousStr  = "my-unique-cluster-service-id" // CHANGE THIS for different clusters
	ReadBufferSize = 32 * 1024                      // 32KB chunks for GCM
)

func main() {
	// --- CLI Flags ---
	mode := flag.String("mode", "client", "Mode: 'relay', 'server', or 'client'")
	target := flag.String("target", "127.0.0.1:8080", "Server: Local App to expose. Client: Local port to listen on.")
	secretKeyPath := flag.String("secret", "swarm.key", "Path to the Private Network Key (PSK)")
	identityPath := flag.String("identity", "", "Path to Identity Key (Default: identity-<mode>.key)")
	relayAddr := flag.String("relay", "", "Multiaddr of the Relay/Bootstrap node (Required for WAN)")
	dataKeyHex := flag.String("datakey", "", "Hex-encoded 32-byte key for AES-GCM data encryption")
	listenPort := flag.Int("port", 0, "Port to listen on (Default: 4001 for relay, random/0 for client/server)")
	flag.Parse()

	// Set default identity filename if not provided
	if *identityPath == "" {
		*identityPath = fmt.Sprintf("identity-%s.key", *mode)
	}

	// Determine final listen port
	finalPort := *listenPort
	if finalPort == 0 && *mode == "relay" {
		finalPort = 4001 // Default relay port
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 0. Parse Data Encryption Key
	var dataKey []byte
	if *dataKeyHex != "" {
		var err error
		dataKey, err = hex.DecodeString(*dataKeyHex)
		if err != nil {
			log.Fatalf("Invalid data key hex: %v", err)
		}
		if len(dataKey) != 32 {
			log.Fatalf("Data key must be 32 bytes (64 hex characters) for AES-256. Got %d bytes.", len(dataKey))
		}
		log.Println("🔒 AES-GCM Authenticated Encryption ENABLED")
	}

	// 1. Load or Generate Identity
	privKey, err := getIdentity(*identityPath)
	if err != nil {
		log.Fatalf("Failed to manage identity: %v", err)
	}

	// 2. Setup Libp2p Host
	h, dhtObj, err := makeHost(ctx, *secretKeyPath, *mode, privKey, *relayAddr, finalPort)
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	log.Printf("-------------------------------------------------")
	log.Printf("Node Started. Mode: %s", strings.ToUpper(*mode))
	log.Printf("Peer ID: %s", h.ID())
	log.Printf("Identity File: %s", *identityPath)
	log.Printf("Listening Port: %d", finalPort)
	log.Printf("-------------------------------------------------")

	// 3. Connect to Relay
	if *mode != "relay" {
		if *relayAddr == "" {
			log.Fatal("❌ Error: Client/Server mode requires a -relay address.")
		}

		log.Printf("🔌 Dialing Relay: %s", *relayAddr)
		connectToPeer(ctx, h, *relayAddr)

		log.Println("⏳ Waiting for DHT routing table update...")
		time.Sleep(2 * time.Second)
	}

	// 4. Start DHT
	log.Println("🔄 Bootstrapping DHT...")
	if err := dhtObj.Bootstrap(ctx); err != nil {
		log.Fatal(err)
	}

	// 5. Execution Logic
	routingDiscovery := routing.NewRoutingDiscovery(dhtObj)

	switch *mode {
	case "relay":
		log.Println("🟢 Relay Active. Waiting for peers...")
		select {}
	case "server":
		runServer(h, routingDiscovery, *target, dataKey)
	case "client":
		runClient(ctx, h, routingDiscovery, *target, dataKey)
	}
}

// --- Host Factory & Identity ---

func makeHost(ctx context.Context, pskPath, mode string, privKey crypto.PrivKey, relayAddrStr string, port int) (host.Host, *dht.IpfsDHT, error) {
	// Construct Listen Addresses
	quicListen := fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port)
	tcpListen := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	var bootstrapPeers []peer.AddrInfo
	if relayAddrStr != "" {
		ma, err := multiaddr.NewMultiaddr(relayAddrStr)
		if err == nil {
			pi, err := peer.AddrInfoFromP2pAddr(ma)
			if err == nil {
				bootstrapPeers = append(bootstrapPeers, *pi)
			}
		}
	}

	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(quicListen, tcpListen),
		// 1. IMPROVED ADDRS FACTORY:
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			var valid []multiaddr.Multiaddr
			for _, addr := range addrs {
				// Always allow Relay Addresses
				if strings.Contains(addr.String(), "p2p-circuit") {
					valid = append(valid, addr)
					continue
				}
				// Allow Public IPs (IPv4/IPv6)
				if manet.IsPublicAddr(addr) {
					valid = append(valid, addr)
					continue
				}
			}

			// FALLBACK: If we have NO valid WAN addresses (Relay or Public),
			// return the original list (Private IPs).
			// This prevents the node from advertising NOTHING and getting stuck.
			if len(valid) == 0 {
				return addrs
			}

			return valid
		}),
	}

	if mode == "relay" {
		opts = append(opts,
			libp2p.EnableRelayService(),
			libp2p.ForceReachabilityPublic(),
			libp2p.EnableNATService(), // IMPORTANT: Helps clients find their public IP
		)
	} else {
		opts = append(opts,
			// 2. ENABLE AUTO RELAY & HOLE PUNCHING
			// We use the relay for connectivity if NAT fails.
			libp2p.EnableAutoRelayWithStaticRelays(bootstrapPeers),
			libp2p.EnableHolePunching(),
			// 3. REMOVED ForceReachabilityPrivate to allow AutoNAT checks
		)
	}

	// STRICT KEY CHECK
	pskFile, err := os.Open(pskPath)
	if err != nil {
		return nil, nil, fmt.Errorf("❌ FATAL: Could not open swarm.key at '%s'. \n   You are running in Private Mode: this file is REQUIRED.\n   Please copy swarm.key to this directory.", pskPath)
	}

	// Calculate fingerprint to help debugging
	pskBytes, _ := io.ReadAll(pskFile)
	pskFile.Seek(0, 0) // Reset read pointer
	hash := sha256.Sum256(pskBytes)
	log.Printf("🔑 Swarm Key Fingerprint: %x (First 6 bytes: %x)", hash, hash[:6])

	psk, err := pnet.DecodeV1PSK(pskFile)
	if err != nil {
		return nil, nil, fmt.Errorf("❌ FATAL: Invalid swarm.key format: %v", err)
	}
	opts = append(opts, libp2p.PrivateNetwork(psk))
	log.Println("🔒 Private Network Mode: ENABLED")

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, nil, err
	}

	// --- DHT Configuration ---

	dhtMode := dht.Mode(dht.ModeClient)
	if mode == "relay" {
		dhtMode = dht.Mode(dht.ModeServer)
	}

	kademliaDHT, err := dht.New(ctx, h,
		dhtMode,
		dht.ProtocolPrefix("/my-private-cluster/kad/1.0.0"),
		dht.BootstrapPeers(bootstrapPeers...),
	)

	return h, kademliaDHT, err
}

func getIdentity(path string) (crypto.PrivKey, error) {
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err == nil {
			return crypto.UnmarshalPrivateKey(data)
		}
	}
	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, err
	}
	data, _ := crypto.MarshalPrivateKey(priv)
	os.WriteFile(path, data, 0600)
	return priv, nil
}

func connectToPeer(ctx context.Context, h host.Host, target string) {
	ma, err := multiaddr.NewMultiaddr(target)
	if err != nil {
		log.Fatalf("❌ Invalid relay address format: %v", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		log.Fatalf("❌ Invalid peer info: %v", err)
	}

	if err := h.Connect(ctx, *info); err != nil {
		log.Printf("❌ Failed to dial Relay %s", info.ID)
		log.Printf("   Error Details: %v", err)
		log.Fatal("   Check: 1. Swarm Key matches?\n2. Is Relay running?\n3. Is IP reachable?")
	}
	log.Println("✅ Connected to Relay successfully.")
}

// --- App Logic ---

func runServer(h host.Host, discovery *routing.RoutingDiscovery, targetPort string, dataKey []byte) {
	// 4. WAIT LOGIC
	// We must NOT advertise to the DHT until we have a usable Public or Relay address.
	// Advertising local IPs (192.168...) causes the client to fail with i/o timeout.
	log.Println("⏳ Analyzing Reachability (AutoNAT/AutoRelay)...")

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			log.Println("⚠️  Reachability checks timed out. Proceeding with available addresses (Fallback mode).")
			log.Println("    If you are on WAN, this might fail unless you have a public IP.")
			goto ADVERTISE
		case <-ticker.C:
			hasUsableAddr := false
			addrs := h.Addrs()

			for _, addr := range addrs {
				// Check for Relay Address (p2p-circuit)
				if strings.Contains(addr.String(), "p2p-circuit") {
					hasUsableAddr = true
				}
				// Check for Public IP (Verified by AutoNAT)
				if manet.IsPublicAddr(addr) {
					hasUsableAddr = true
				}
			}

			if hasUsableAddr {
				log.Println("✅ Valid WAN Address confirmed. Advertising service to cluster...")
				// Log what we are actually advertising
				for _, a := range addrs {
					log.Printf("   - %s", a)
				}
				goto ADVERTISE
			}
			log.Println("... Waiting for Public/Relay address resolution ...")
		}
	}

ADVERTISE:
	dutil.Advertise(context.Background(), discovery, RendezvousStr)

	h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
		log.Printf("New Connection from %s", s.Conn().RemotePeer())
		local, err := net.Dial("tcp", targetPort)
		if err != nil {
			log.Printf("Failed to dial local service: %v", err)
			s.Reset()
			return
		}
		proxy(s, local, dataKey)
	})
	log.Printf("✅ Server Ready. Forwarding to %s", targetPort)
	select {}
}

func runClient(ctx context.Context, h host.Host, discovery *routing.RoutingDiscovery, localPort string, dataKey []byte) {
	var serverPeer peer.AddrInfo

	log.Println("🔍 Starting discovery loop...")

	for {
		log.Println("🔎 Searching DHT for server peer...")
		peerChan, err := discovery.FindPeers(ctx, RendezvousStr)
		if err != nil {
			log.Printf("⚠️ Discovery error: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		found := false
		for p := range peerChan {
			if p.ID == h.ID() {
				continue
			}
			// We found someone!
			log.Printf("✨ Discovered Peer: %s. Connecting...", p.ID)

			if err := h.Connect(ctx, p); err != nil {
				log.Printf("⚠️ Connection failed to %s: %v", p.ID, err)
				continue
			}

			serverPeer = p
			found = true
			log.Printf("✅ Connection Established to Server: %s", p.ID)
			break
		}

		if found {
			break
		}

		log.Println("... No peers found yet. Retrying in 3s...")
		time.Sleep(3 * time.Second)
	}

	// Start Local Listener
	listener, err := net.Listen("tcp", localPort)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("🚀 Tunnel Active! Listening on %s", localPort)
	log.Printf("➡️  Traffic will be forwarded to Peer %s", serverPeer.ID)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Listener error:", err)
			continue
		}
		go func(c net.Conn) {
			s, err := h.NewStream(ctx, serverPeer.ID, TunnelProtocol)
			if err != nil {
				log.Printf("Failed to open stream to peer: %v", err)
				c.Close()
				return
			}
			proxy(s, c, dataKey)
		}(conn)
	}
}

// --- AES-GCM Proxy Logic ---

func proxy(stream network.Stream, tcpConn net.Conn, key []byte) {
	var wg sync.WaitGroup
	wg.Add(2)

	// 1. Local TCP -> Remote Libp2p (Encrypt)
	go func() {
		defer wg.Done()
		if len(key) > 0 {
			if err := gcmEncryptLoop(tcpConn, stream, key); err != nil {
				// Silent fail on close is expected
			}
		} else {
			io.Copy(stream, tcpConn)
		}
		stream.CloseWrite()
	}()

	// 2. Remote Libp2p -> Local TCP (Decrypt)
	go func() {
		defer wg.Done()
		if len(key) > 0 {
			if err := gcmDecryptLoop(stream, tcpConn, key); err != nil {
				// Silent fail on close is expected
			}
		} else {
			io.Copy(tcpConn, stream)
		}
		if t, ok := tcpConn.(*net.TCPConn); ok {
			t.CloseWrite()
		} else {
			tcpConn.Close()
		}
	}()

	wg.Wait()
	stream.Close()
	tcpConn.Close()
}

// AES-GCM Encryption Loop (Chunked)
func gcmEncryptLoop(src io.Reader, dst io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, ReadBufferSize)
	header := make([]byte, 4+gcm.NonceSize())

	for {
		n, err := src.Read(buf)
		if n > 0 {
			nonce := header[4:]
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}

			ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)
			totalLen := uint32(len(nonce) + len(ciphertext))
			binary.BigEndian.PutUint32(header[:4], totalLen)

			if _, err := dst.Write(header[:4]); err != nil {
				return err
			}
			if _, err := dst.Write(nonce); err != nil {
				return err
			}
			if _, err := dst.Write(ciphertext); err != nil {
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// AES-GCM Decryption Loop (Chunked)
func gcmDecryptLoop(src io.Reader, dst io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	lenBuf := make([]byte, 4)
	nonce := make([]byte, gcm.NonceSize())

	for {
		if _, err := io.ReadFull(src, lenBuf); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		totalLen := binary.BigEndian.Uint32(lenBuf)

		if totalLen > ReadBufferSize+uint32(gcm.Overhead())+uint32(gcm.NonceSize()) {
			return fmt.Errorf("oversized chunk")
		}

		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}

		cipherLen := totalLen - uint32(len(nonce))
		cipherBuf := make([]byte, cipherLen)
		if _, err := io.ReadFull(src, cipherBuf); err != nil {
			return err
		}

		plaintext, err := gcm.Open(nil, nonce, cipherBuf, nil)
		if err != nil {
			return err
		}

		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
	}
}
