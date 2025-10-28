package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-profile/internal/probe"
)

var (
	hwEvent   = flag.Bool("hw", false, "Use hardware event (PERF_TYPE_HARDWARE) instead of software event (PERF_TYPE_SOFTWARE)")
	freq   = flag.Int("freq", 1000000, "Sampling frequency in Hz")
    pidFilter = flag.Int("pid", -1, "Filter by PID (default: -1, meaning all PIDs)")
	printStack   = flag.Bool("ps", false, "Print stack traces")
)

func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

func main() {
	flag.Parse()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)
	if err := probe.Run(ctx, *hwEvent, *freq, *pidFilter, *printStack); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}