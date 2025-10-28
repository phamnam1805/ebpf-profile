package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

const MaxStackDepth = 128

type StacktraceEvent struct {
    Pid        	uint32
    CpuId      	uint32
    Timestamp  	uint64
	Comm        [16]byte
    KStackSz    int32
    UStackSz    int32
    KStack      [MaxStackDepth]uint64
    UStack      [MaxStackDepth]uint64
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func UnmarshalBinary(data []byte) (*StacktraceEvent, error) {
    var event StacktraceEvent
    reader := bytes.NewReader(data)
    if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
        return nil, err
    }
    return &event, nil
}

func PrintEventInfo(e *StacktraceEvent, bootTimestampNs uint64, printStack bool) {
    // timestamp := time.Now().Format("15:04:05")
    comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

	unixTimestampNs := bootTimestampNs + e.Timestamp
    fmt.Printf("%-20d %-24s %-7d %-7d %-7d %-7d\n",
        unixTimestampNs, comm, e.Pid, e.CpuId, e.KStackSz, e.UStackSz)
	
	if printStack {
		fmt.Print("KStack: [")
		for i := 0; i < min(int(e.KStackSz), MaxStackDepth); i++ {
			fmt.Printf("%#x ", e.KStack[i])
		}
		fmt.Println("]")

		fmt.Print("UStack: [")
		for i := 0; i < min(int(e.UStackSz), MaxStackDepth); i++ {
			fmt.Printf("%#x ", e.UStack[i])
		}
		fmt.Println("]")
	}
}

