package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
)

const (
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorCyan      = "\033[36m"
	colorBoldCyan  = "\033[1;36m"
	colorYellow    = "\033[33m"
	colorBoldWhite = "\033[1;37m"
	colorGreen     = "\033[32m"
	colorMagenta   = "\033[35m"
	colorBlue      = "\033[34m"
	colorGray      = "\033[90m"
)

var frameColors = []string{
	colorBoldCyan,
	colorGreen,
	colorYellow,
	colorMagenta,
	colorBlue,
	colorBoldWhite,
}

// frameColor cycles through the palette of frame colors by index.
func frameColor(i int) string {
	return frameColors[i%len(frameColors)]
}

const (
	THREAD_GET_CONTEXT       = 0x0008
	THREAD_QUERY_INFORMATION = 0x0040
	THREAD_SUSPEND_RESUME    = 0x0002
	CONTEXT_FULL             = 0x00100007
	INVALID_HANDLE_VALUE     = ^uintptr(0)
)

type M128A struct {
	Low  uint64
	High int64
}

type XMM_SAVE_AREA32 struct {
	ControlWord    uint16
	StatusWord     uint16
	TagWord        uint8
	Reserved1      uint8
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]uint8
}

type CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags uint32
	MxCsr        uint32

	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	Rax     uint64
	Rcx     uint64
	Rdx     uint64
	Rbx     uint64
	Rsp     uint64
	Rbp     uint64
	Rsi     uint64
	Rdi     uint64
	R8      uint64
	R9      uint64
	R10     uint64
	R11     uint64
	R12     uint64
	R13     uint64
	R14     uint64
	R15     uint64
	Rip     uint64
	FltSave XMM_SAVE_AREA32

	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// traceThreadStack suspends a thread, captures its context and unwinds the stack and prints the resolved frames.
func traceThreadStack(pid uint32, hProcess uintptr, modules []moduleInfo, tid uint32) {
	cid := CLIENT_ID{UniqueThread: uintptr(tid)}
	oa := newObjectAttributes()
	var hThread uintptr
	status, _ := wincall.IndirectSyscall(sc.ntOpenThread.ssn, sc.ntOpenThread.addr,
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION|THREAD_SUSPEND_RESUME),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	if status != 0 {
		// STATUS_INVALID_CID (0xC000000B) means thread already exited
		if uint32(status) != 0xC000000B {
			fmt.Fprintf(os.Stderr, "[-] NtOpenThread failed for TID %d (status 0x%x)\n", tid, uint32(status))
		}
		return
	}
	defer wincall.IndirectSyscall(sc.ntClose.ssn, sc.ntClose.addr, hThread)

	wincall.IndirectSyscall(sc.ntSuspendThread.ssn, sc.ntSuspendThread.addr, hThread, uintptr(0))
	defer wincall.IndirectSyscall(sc.ntResumeThread.ssn, sc.ntResumeThread.addr, hThread, uintptr(0))

	// CONTEXT must be 16 byte aligned and th Go heap doesn't guarantee that
	// so we allocate extra space and align the pointer manually, this is annoying but necessary to not crash
	ctxBuf := make([]byte, unsafe.Sizeof(CONTEXT{})+16)
	ctxPtr := (uintptr(unsafe.Pointer(&ctxBuf[0])) + 15) &^ 15
	ctx := (*CONTEXT)(unsafe.Pointer(ctxPtr))
	ctx.ContextFlags = CONTEXT_FULL

	ctxStatus, _ := wincall.IndirectSyscall(sc.ntGetContextThread.ssn, sc.ntGetContextThread.addr,
		hThread,
		ctxPtr,
	)
	if ctxStatus != 0 {
		fmt.Fprintf(os.Stderr, "[!] NtGetContextThread failed (status 0x%x)\n", uint32(ctxStatus))
		return
	}

	r := ctxToRegFile(ctx)
	var entries []string
	const maxFrames = 128

	for len(entries) < maxFrames {
		if r.rip == 0 {
			break
		}
		entries = append(entries, resolveAddressNT(hProcess, modules, r.rip))
		regFileToCtx(&r, ctx)
		if !virtualUnwind(hProcess, modules, &r) {
			break
		}
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s┌─ PID: %s%d%s  TID: %s%d%s\n",
		colorGray,
		colorBoldCyan, pid, colorGray,
		colorYellow, tid, colorReset,
	))

	if len(entries) == 0 {
		sb.WriteString(fmt.Sprintf("%s└─ %s(empty)%s\n", colorGray, colorDim, colorReset))
	} else {
		last := len(entries) - 1
		for i, e := range entries {
			prefix := "├─"
			if i == last {
				prefix = "└─"
			}
			colored := colorizeFrame(e, i)
			sb.WriteString(fmt.Sprintf("%s%s%s [%s%d%s] %s\n",
				colorGray, prefix, colorReset,
				colorDim, i, colorReset,
				colored,
			))
		}
	}

	fmt.Print(sb.String())
}

// colorizeFrame applies ansi color to module, symbol, and offset parts of a frame string.
func colorizeFrame(frame string, idx int) string {
	fc := frameColor(idx)
	if bang := strings.IndexByte(frame, '!'); bang != -1 {
		module := frame[:bang]
		rest := frame[bang+1:]
		plus := strings.LastIndexByte(rest, '+')
		if plus != -1 {
			symbol := rest[:plus]
			offset := rest[plus:]
			return fmt.Sprintf("%s%s%s!%s%s%s%s%s%s",
				colorBold, module, colorReset,
				fc, symbol, colorReset,
				colorGray, offset, colorReset,
			)
		}
		return fmt.Sprintf("%s%s%s!%s%s%s", colorBold, module, colorReset, fc, rest, colorReset)
	}
	if plus := strings.LastIndexByte(frame, '+'); plus != -1 {
		base := frame[:plus]
		offset := frame[plus:]
		return fmt.Sprintf("%s%s%s%s%s%s", fc, base, colorReset, colorGray, offset, colorReset)
	}
	return fmt.Sprintf("%s%s%s", colorGray, frame, colorReset)
}
