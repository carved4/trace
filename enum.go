package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
)

const (
	SystemProcessInformation = 5
	StatusInfoLengthMismatch = 0xC0000004
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	Buffer        uintptr
}

type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    UNICODE_STRING
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	HandleCount                  uint32
	SessionId                    uint32
	UniqueProcessKey             uintptr
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
}

// findPidByName searches the system process list for a process whose name contains name (case-insensitive).
func findPidByName(name string) (uint32, error) {
	bufSize := uintptr(1 << 19)
	var buf []byte

	for {
		buf = make([]byte, bufSize)
		var returnLength uint32

		status, _ := wincall.IndirectSyscall(sc.ntQuerySystemInformation.ssn, sc.ntQuerySystemInformation.addr,
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			bufSize,
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if uintptr(status) == StatusInfoLengthMismatch {
			bufSize = uintptr(returnLength) + 4096
			continue
		}
		if status != 0 {
			return 0, fmt.Errorf("NtQuerySystemInformation failed: 0x%x", status)
		}
		break
	}

	offset := uintptr(0)
	for {
		entry := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[offset]))

		if entry.ImageName.Length > 0 && entry.ImageName.Buffer != 0 {
			nameSlice := (*[512]uint16)(unsafe.Pointer(entry.ImageName.Buffer))[: entry.ImageName.Length/2 : entry.ImageName.Length/2]
			procName := string(utf16.Decode(nameSlice))
			lName := strings.ToLower(name)
			lProc := strings.ToLower(procName)
			if strings.Contains(lName, lProc) || strings.Contains(lProc, lName) {
				return uint32(entry.UniqueProcessId), nil
			}
		}

		if entry.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(entry.NextEntryOffset)
	}

	return 0, fmt.Errorf("process %q not found", name)
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	_                        uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	_                        uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// newObjectAttributes returns a zeroed OBJECT_ATTRIBUTES with Length initialised.
func newObjectAttributes() OBJECT_ATTRIBUTES {
	return OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{}))}
}

type SYSTEM_THREAD_INFORMATION struct {
	KernelTime      int64
	UserTime        int64
	CreateTime      int64
	WaitTime        uint32
	_               uint32
	StartAddress    uintptr
	ClientId        CLIENT_ID
	Priority        int32
	BasePriority    int32
	ContextSwitches uint32
	ThreadState     uint32
	WaitReason      uint32
	_               uint32
}

// collectThreads returns all thread IDs for pid, or just tid if non-zero.
func collectThreads(pid, tid uint32) []uint32 {
	var threads []uint32

	bufSize := uintptr(1 << 19)
	var buf []byte

	for {
		buf = make([]byte, bufSize)
		var returnLength uint32

		status, _ := wincall.IndirectSyscall(sc.ntQuerySystemInformation.ssn, sc.ntQuerySystemInformation.addr,
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			bufSize,
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if uintptr(status) == StatusInfoLengthMismatch {
			bufSize = uintptr(returnLength) + 4096
			continue
		}
		if status != 0 {
			fmt.Fprintf(os.Stderr, "[-] NtQuerySystemInformation failed: 0x%x\n", status)
			return threads
		}
		break
	}

	offset := uintptr(0)
	for {
		entry := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[offset]))

		if uint32(entry.UniqueProcessId) == pid {
			threadBase := offset + unsafe.Sizeof(SYSTEM_PROCESS_INFORMATION{})
			for i := uint32(0); i < entry.NumberOfThreads; i++ {
				t := (*SYSTEM_THREAD_INFORMATION)(unsafe.Pointer(&buf[threadBase+uintptr(i)*unsafe.Sizeof(SYSTEM_THREAD_INFORMATION{})]))
				threadID := uint32(t.ClientId.UniqueThread)
				if tid == 0 {
					threads = append(threads, threadID)
				} else if tid == threadID {
					return []uint32{threadID}
				}
			}
			if tid != 0 {
				fmt.Fprintln(os.Stderr, "[-] Target thread not found!")
				os.Exit(-1)
			}
			return threads
		}

		if entry.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(entry.NextEntryOffset)
	}

	return threads
}
