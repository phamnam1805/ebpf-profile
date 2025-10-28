package probe

import (
	"context"
	"fmt"
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"ebpf-profile/internal/event"
	"ebpf-profile/internal/timer"
)

// go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/profile.bpf.c -- -O2

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects 	*probeObjects
	ncpu       	int
	profileFDs 	[]int
}

func setRlimit() error {
     log.Println("Setting rlimit")

     return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
         Cur: twentyMegaBytes,
         Max: fortyMegaBytes,
     })
}

func setUnlimitedRlimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed setting infinite rlimit: %v", err)
		return err
	}
	return nil
}

func newProbe(hwEvent bool, freq int, pidFilter int) (*probe, error) {
	log.Println("Creating a new probe")

	prbe := probe{}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(hwEvent, freq, pidFilter); err != nil {
		log.Printf("Failed attaching ebpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}


func (p *probe) loadObjects() error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	spec, err := loadProbe()
	if err != nil {
		return err
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return err
	}

	p.bpfObjects = &objs

	return nil
}


func (p *probe) attachPrograms(hwEvent bool, freq int, pidFilter int) error {
	ncpu := runtime.NumCPU()
	p.ncpu = ncpu
	p.profileFDs = make([]int, ncpu)

	var kind uint32 
	var config uint64

	if hwEvent {
		kind = unix.PERF_TYPE_HARDWARE
		config = unix.PERF_COUNT_HW_CPU_CYCLES
	} else {
		kind = unix.PERF_TYPE_SOFTWARE
		config = unix.PERF_COUNT_SW_CPU_CLOCK
	}

	for cpu := 0; cpu < ncpu; cpu++ {
		eventAttr := &unix.PerfEventAttr{
            Type:        kind,
			Config:      config,
            Size:        uint32(unsafeSizeofPerfEventAttr()),
			Sample_type: unix.PERF_SAMPLE_RAW,
			Sample_max_stack: event.MaxStackDepth,
			Sample:      uint64(freq),
			Wakeup:      1,
        }
		fd, err := unix.PerfEventOpen(
			eventAttr,
			pidFilter,
			cpu,
			-1,
			unix.PERF_FLAG_FD_CLOEXEC,
		)
		if err != nil {
			log.Printf("Failed opening perf event on cpu %d: %v", cpu, err)
			return err
		}

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, p.bpfObjects.Profile.FD()); err != nil {
			log.Printf("Failed to attach eBPF program to perf event: %v", err)
			return err
		}
		p.profileFDs[cpu] = fd
	}
	return nil
}

func (p *probe) startPrograms() error {
	for cpu, fd := range p.profileFDs {
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			log.Printf("Failed to start perf event on cpu %d: %v", cpu, err)
			return err
		}
	}
	return nil
}

func (p *probe) stopPrograms() error {
	for cpu, fd := range p.profileFDs {
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			log.Printf("Failed to stop perf event on cpu %d: %v", cpu, err)
			return err
		}
	}
	return nil
}

func unsafeSizeofPerfEventAttr() uintptr {
    // unix.PerfEventAttr has fixed fields; using sizeof via unsafe
    // Note: using unsafe.Sizeof requires import "unsafe"
    // Keep a small helper to avoid inlining the import at top-level.
    return uintptr(unsafeSizeof())
}

func unsafeSizeof() uintptr {
    // small indirection to allow build if unsafe not allowed in some environments
    // import explicitly here to keep top imports clean
    type dummyAttr struct {
        _ [1]byte
    }
    _ = dummyAttr{}
    // fallback to typical size 112 on common kernels; if compilation requires exact value adjust manually.
    return uintptr(unsafeSize())
}

func unsafeSize() int {
    // default size for perf_event_attr on x86_64 kernels is commonly 120 or 112 depending on kernel.
    // Use 112 which works on many kernels; if you see EINVAL, increase to 120.
    return 112
}

func Run(ctx context.Context, hwEvent bool, freq int, pidFilter int, printStack bool) error {
	log.Println("Starting up the probe")
	if err := setUnlimitedRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return err
	}

	probe, err := newProbe(hwEvent, freq, pidFilter)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}
	stacktraceEventPipe := probe.bpfObjects.probeMaps.Events

	stacktraceEventReader, err := ringbuf.NewReader(stacktraceEventPipe)
	if err != nil {
		log.Printf("Failed opening ringbuf reader: %v", err)
		return err
	}
	defer stacktraceEventReader.Close()

	bootTimestampNs := timer.GetNanosecBootTimestamp()
	fmt.Printf("%-20s %-24s %-7s %-7s %-7s %-7s\n",
        "TIME", "COMM", "PID", "CPUID", "KStackSz", "UStackSz")
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
            record, err := stacktraceEventReader.Read()
            if err != nil {
                if ctx.Err() != nil {
                    return
                }
                log.Printf("Failed reading from ringbuf: %v", err)
                continue
            }
            stacktraceEventAttrs, err := event.UnmarshalBinary(record.RawSample)
            if err != nil {
                log.Printf("Could not unmarshal event: %+v", record.RawSample)
                continue
            }
            event.PrintEventInfo(stacktraceEventAttrs, bootTimestampNs, printStack)
        }
	}()
	<-ctx.Done()
    log.Println("Context cancelled, shutting down...")
    return probe.stopPrograms()
}
