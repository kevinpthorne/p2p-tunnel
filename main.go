package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/multiformats/go-multiaddr"
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
	identityPath := flag.String("identity", "identity.key", "Path to store/load the Node Identity Key")
	relayAddr := flag.String("relay", "", "Multiaddr of the Relay/Bootstrap node (Required for WAN). e.g. /ip4/1.2.3.4/udp/4001/quic-v1/p2p/abc...")
	dataKeyHex := flag.String("datakey", "", "Hex-encoded 32-byte key for AES-GCM data encryption")
	flag.Parse()

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
	h, dhtObj, err := makeHost(ctx, *secretKeyPath, *mode, privKey, *relayAddr)
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}
	defer h.Close()

	log.Printf("-------------------------------------------------")
	log.Printf("Node Started. Mode: %s", strings.ToUpper(*mode))
	log.Printf("Peer ID: %s", h.ID())
	log.Printf("-------------------------------------------------")

	// 3. Connect to Relay
	if *mode != "relay" {
		if *relayAddr == "" {
			log.Fatal("❌ Error: Client/Server mode requires a -relay address.")
		}
		connectToPeer(ctx, h, *relayAddr)

		// Wait a moment for the DHT to acknowledge the new connection
		log.Println("⏳ Waiting for DHT routing table update...")
		time.Sleep(2 * time.Second)
	}

	// 4. Start DHT
	log.Println("Bootstrapping DHT...")
	if err := dhtObj.Bootstrap(ctx); err != nil {
		log.Fatal(err)
	}

	// 5. Execution Logic
	routingDiscovery := routing.NewRoutingDiscovery(dhtObj)

	switch *mode {
	case "relay":
		log.Println("🟢 Relay Active.")
		select {}
	case "server":
		dutil.Advertise(ctx, routingDiscovery, RendezvousStr)
		runServer(h, *target, dataKey)
	case "client":
		runClient(ctx, h, routingDiscovery, *target, dataKey)
	}
}

// --- Host Factory & Identity (Same as before) ---
func makeHost(ctx context.Context, pskPath, mode string, privKey crypto.PrivKey, relayAddrStr string) (host.Host, *dht.IpfsDHT, error) {
	rm := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ResourceManager(rm),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"),
		libp2p.EnableHolePunching(),
	}

	if mode == "relay" {
		opts = []libp2p.Option{
			libp2p.Identity(privKey),
			libp2p.ResourceManager(rm),
			libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4001"),
			libp2p.EnableRelayService(),
			libp2p.ForceReachabilityPublic(),
		}
	} else {
		opts = append(opts, libp2p.ForceReachabilityPrivate())
	}

	pskFile, err := os.Open(pskPath)
	if err == nil {
		psk, err := pnet.DecodeV1PSK(pskFile)
		if err == nil {
			opts = append(opts, libp2p.PrivateNetwork(psk))
		}
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, nil, err
	}

	// --- DHT Configuration (The Fix) ---

	// 1. Define DHT Mode
	dhtMode := dht.Mode(dht.ModeClient)
	if mode == "relay" {
		dhtMode = dht.Mode(dht.ModeServer)
	}

	// 2. Define Bootstrap Peers
	// If we are a Client/Server, we MUST bootstrap from the Relay.
	// If we don't specify this, Libp2p uses public defaults (IPFS nodes), which hang.
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

	// 3. Create DHT with Explicit Options
	kademliaDHT, err := dht.New(ctx, h,
		dhtMode,
		// CRITICAL: Force the DHT to use our private protocol name.
		// This stops it from merging with the public IPFS DHT.
		dht.ProtocolPrefix("/my-private-cluster/kad/1.0.0"),
		// CRITICAL: Only use our relay as a bootstrap peer.
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
	ma, _ := multiaddr.NewMultiaddr(target)
	info, _ := peer.AddrInfoFromP2pAddr(ma)
	h.Connect(ctx, *info)
	log.Println("✅ Connected to Relay.")
}

// --- App Logic ---

func runServer(h host.Host, targetPort string, dataKey []byte) {
	h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
		log.Printf("New Connection from %s", s.Conn().RemotePeer())
		local, err := net.Dial("tcp", targetPort)
		if err != nil {
			s.Reset()
			return
		}
		proxy(s, local, dataKey)
	})
	log.Printf("Server Ready. Forwarding to %s", targetPort)
	select {}
}

func runClient(ctx context.Context, h host.Host, discovery *routing.RoutingDiscovery, localPort string, dataKey []byte) {
	var serverPeer peer.AddrInfo
	for {
		peerChan, _ := discovery.FindPeers(ctx, RendezvousStr)
		for p := range peerChan {
			if p.ID == h.ID() {
				continue
			}
			if err := h.Connect(ctx, p); err == nil {
				serverPeer = p
				log.Printf("✅ Connected to Server: %s", p.ID)
				goto CONNECTED
			}
		}
		time.Sleep(2 * time.Second)
	}

CONNECTED:
	listener, err := net.Listen("tcp", localPort)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("🚀 Tunnel Listening on %s", localPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			s, err := h.NewStream(ctx, serverPeer.ID, TunnelProtocol)
			if err != nil {
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
				// log.Printf("Encryption stream ended: %v", err)
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
				// log.Printf("Decryption stream ended: %v", err)
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

	// Buffer for reading plaintext
	buf := make([]byte, ReadBufferSize)
	// Buffer for framing: Length (4) + Nonce (12)
	header := make([]byte, 4+gcm.NonceSize())

	for {
		// 1. Read plaintext chunk
		n, err := src.Read(buf)
		if n > 0 {
			// 2. Generate Nonce
			nonce := header[4:] // Use the slice directly
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}

			// 3. Encrypt (Seal appends tag to ciphertext)
			// We append directly to a nil slice to let Seal allocate,
			// or we could optimize allocation here.
			ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)

			// 4. Prepare Header: Length of [Nonce + Ciphertext]
			// Actually, standard is usually Length of just Ciphertext,
			// but we need to know how much to read on the other side.
			// Let's transmit [Len][Nonce][Ciphertext+Tag]

			totalLen := uint32(len(nonce) + len(ciphertext))
			binary.BigEndian.PutUint32(header[:4], totalLen)

			// 5. Write Header (Len)
			if _, err := dst.Write(header[:4]); err != nil {
				return err
			}
			// 6. Write Nonce
			if _, err := dst.Write(nonce); err != nil {
				return err
			}
			// 7. Write Ciphertext + Tag
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
		// 1. Read Length Header
		if _, err := io.ReadFull(src, lenBuf); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		totalLen := binary.BigEndian.Uint32(lenBuf)

		// 2. Validate Length (Sanity check)
		if totalLen > ReadBufferSize+uint32(gcm.Overhead())+uint32(gcm.NonceSize()) {
			return fmt.Errorf("oversized chunk received: %d", totalLen)
		}

		// 3. Read Nonce
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}

		// 4. Read Ciphertext + Tag
		// Length of ciphertext is totalLen - len(nonce)
		cipherLen := totalLen - uint32(len(nonce))
		cipherBuf := make([]byte, cipherLen)
		if _, err := io.ReadFull(src, cipherBuf); err != nil {
			return err
		}

		// 5. Decrypt (Open)
		plaintext, err := gcm.Open(nil, nonce, cipherBuf, nil)
		if err != nil {
			return fmt.Errorf("decryption failed (tampering detected?): %v", err)
		}

		// 6. Write Plaintext
		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
	}
}
