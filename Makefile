generate: 
	go generate ./...

build-ebpf-profile:
	go build -ldflags "-s -w" -o ebpf-profile cmd/main.go

build: generate build-ebpf-profile

clean:
	rm -f ebpf-profile
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o