go build -o p2p-tunnel.darwin-arm64 main.go
GOOS=windows GOARCH=amd64 go build -o p2p-tunnel.win-amd64.exe main.go
GOOS=linux GOARCH=amd64 go build -o p2p-tunnel.linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o p2p-tunnel.linux-arm64 main.go