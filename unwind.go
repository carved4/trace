// unwind.go implements x64 stack unwinding and symbol resolution without dbghelp.
// it reads the target process's PEB to enumerate loaded modules, parses each module's
// PE headers to extract the .pdata exception directory (RUNTIME_FUNCTION table), and
// interprets x64 unwind codes to walk frames. symbols are resolved by scanning PE
// export tables directly via NtReadVirtualMemory. for leaf frames or frames with no
// unwind record, a fallback RSP scan finds the next valid return address.
package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
)

const (
	ProcessBasicInformation = 0

	pebLdrOffset         = 0x18
	ldrInLoadOrderOffset = 0x10

	ldrFlink       = 0x00
	ldrDllBase     = 0x30
	ldrSizeOfImage = 0x40
	ldrBaseDllName = 0x58

	UWOP_PUSH_NONVOL     = 0
	UWOP_ALLOC_LARGE     = 1
	UWOP_ALLOC_SMALL     = 2
	UWOP_SET_FPREG       = 3
	UWOP_SAVE_NONVOL     = 4
	UWOP_SAVE_NONVOL_FAR = 5
	UWOP_EPILOG          = 6
	UWOP_SPARE           = 7
	UWOP_SAVE_XMM128     = 8
	UWOP_SAVE_XMM128_FAR = 9
	UWOP_PUSH_MACHFRAME  = 10

	UNW_FLAG_CHAININFO = 0x4
)

type ntSCI struct {
	ssn  uint32
	addr uintptr
}

func getSCI(name string) ntSCI {
	s := wincall.GetSyscall(wincall.GetHash(name))
	return ntSCI{ssn: s.SSN, addr: s.Address}
}

type syscallCache struct {
	ntReadVirtualMemory       ntSCI
	ntQueryInformationProcess ntSCI
	ntQuerySystemInformation  ntSCI
	ntOpenProcess             ntSCI
	ntOpenThread              ntSCI
	ntClose                   ntSCI
	ntSuspendThread           ntSCI
	ntResumeThread            ntSCI
	ntGetContextThread        ntSCI
}

var sc syscallCache

// resolve early so no overhead during actual ops
func initSyscalls() {
	sc.ntReadVirtualMemory = getSCI("NtReadVirtualMemory")
	sc.ntQueryInformationProcess = getSCI("NtQueryInformationProcess")
	sc.ntQuerySystemInformation = getSCI("NtQuerySystemInformation")
	sc.ntOpenProcess = getSCI("NtOpenProcess")
	sc.ntOpenThread = getSCI("NtOpenThread")
	sc.ntClose = getSCI("NtClose")
	sc.ntSuspendThread = getSCI("NtSuspendThread")
	sc.ntResumeThread = getSCI("NtResumeThread")
	sc.ntGetContextThread = getSCI("NtGetContextThread")
}

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

type moduleInfo struct {
	base        uint64
	size        uint32
	name        string
	displayName string
	pdata       []runtimeFunction
}

type runtimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

type regFile struct {
	gp  [16]uint64
	rip uint64
}

// readRemote reads len(buf) bytes from addr in the target process.
func readRemote(hProcess uintptr, addr uint64, buf []byte) bool {
	if len(buf) == 0 {
		return true
	}
	var bytesRead uintptr
	status, _ := wincall.IndirectSyscall(sc.ntReadVirtualMemory.ssn, sc.ntReadVirtualMemory.addr,
		hProcess,
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	return status == 0 && int(bytesRead) == len(buf)
}

func readU8(hProcess uintptr, addr uint64) (uint8, bool) {
	var b [1]byte
	ok := readRemote(hProcess, addr, b[:])
	return b[0], ok
}

func readU16(hProcess uintptr, addr uint64) (uint16, bool) {
	var b [2]byte
	ok := readRemote(hProcess, addr, b[:])
	return binary.LittleEndian.Uint16(b[:]), ok
}

func readU32(hProcess uintptr, addr uint64) (uint32, bool) {
	var b [4]byte
	ok := readRemote(hProcess, addr, b[:])
	return binary.LittleEndian.Uint32(b[:]), ok
}

func readU64(hProcess uintptr, addr uint64) (uint64, bool) {
	var b [8]byte
	ok := readRemote(hProcess, addr, b[:])
	return binary.LittleEndian.Uint64(b[:]), ok
}

func readUTF16Remote(hProcess uintptr, addr uint64, nChars int) string {
	if nChars <= 0 {
		return ""
	}
	buf := make([]byte, nChars*2)
	if !readRemote(hProcess, addr, buf) {
		return ""
	}
	u16 := make([]uint16, nChars)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return string(utf16.Decode(u16))
}

// enumModules returns all modules loaded in the target process via the PEB module list.
func enumModules(hProcess uintptr) []moduleInfo {
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	status, _ := wincall.IndirectSyscall(sc.ntQueryInformationProcess.ssn, sc.ntQueryInformationProcess.addr,
		hProcess,
		uintptr(ProcessBasicInformation),
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if status != 0 {
		return nil
	}

	ldrPtr, ok := readU64(hProcess, uint64(pbi.PebBaseAddress)+pebLdrOffset)
	if !ok || ldrPtr == 0 {
		return nil
	}

	listHead := ldrPtr + ldrInLoadOrderOffset
	flink, ok := readU64(hProcess, listHead)
	if !ok {
		return nil
	}

	var modules []moduleInfo
	visited := make(map[uint64]bool)

	for flink != listHead {
		if visited[flink] {
			break
		}
		visited[flink] = true

		entryBase := flink

		dllBase, _ := readU64(hProcess, entryBase+ldrDllBase)
		sizeOfImage, _ := readU32(hProcess, entryBase+ldrSizeOfImage)

		nameLen, _ := readU16(hProcess, entryBase+ldrBaseDllName)
		namePtr, _ := readU64(hProcess, entryBase+ldrBaseDllName+8)
		name := readUTF16Remote(hProcess, namePtr, int(nameLen/2))

		nextFlink, ok := readU64(hProcess, flink+ldrFlink)
		if !ok {
			break
		}

		if dllBase != 0 && sizeOfImage != 0 {
			mi := moduleInfo{
				base:        dllBase,
				size:        sizeOfImage,
				name:        strings.ToLower(name),
				displayName: name,
			}
			mi.pdata = readPdata(hProcess, mi)
			modules = append(modules, mi)
		}

		flink = nextFlink
	}

	return modules
}

// readPdata reads and returns the exception directory (RUNTIME_FUNCTION array) from a remote module.
func readPdata(hProcess uintptr, mi moduleInfo) []runtimeFunction {
	base := mi.base

	elfanew, ok := readU32(hProcess, base+0x3C)
	if !ok {
		return nil
	}
	ntHdr := base + uint64(elfanew)

	sig, ok := readU32(hProcess, ntHdr)
	if !ok || sig != 0x00004550 {
		return nil
	}

	ddExceptionRVA, ok := readU32(hProcess, ntHdr+24+0x70+3*8)
	if !ok || ddExceptionRVA == 0 {
		return nil
	}
	ddExceptionSize, ok := readU32(hProcess, ntHdr+24+0x70+3*8+4)
	if !ok || ddExceptionSize == 0 {
		return nil
	}

	count := int(ddExceptionSize) / 12
	buf := make([]byte, ddExceptionSize)
	if !readRemote(hProcess, base+uint64(ddExceptionRVA), buf) {
		return nil
	}

	funcs := make([]runtimeFunction, count)
	for i := range funcs {
		o := i * 12
		funcs[i].BeginAddress = binary.LittleEndian.Uint32(buf[o:])
		funcs[i].EndAddress = binary.LittleEndian.Uint32(buf[o+4:])
		funcs[i].UnwindData = binary.LittleEndian.Uint32(buf[o+8:])
	}

	sort.Slice(funcs, func(a, b int) bool {
		return funcs[a].BeginAddress < funcs[b].BeginAddress
	})
	return funcs
}

// lookupRuntimeFunction binary-searches the .pdata table for the entry covering pc.
func lookupRuntimeFunction(mi *moduleInfo, pc uint64) *runtimeFunction {
	if pc < mi.base || pc >= mi.base+uint64(mi.size) {
		return nil
	}
	rva := uint32(pc - mi.base)
	funcs := mi.pdata
	lo, hi := 0, len(funcs)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if rva < funcs[mid].BeginAddress {
			hi = mid - 1
		} else if rva >= funcs[mid].EndAddress {
			lo = mid + 1
		} else {
			return &funcs[mid]
		}
	}
	return nil
}

// ctxToRegFile copies integer registers from a CONTEXT into a regFile.
func ctxToRegFile(ctx *CONTEXT) regFile {
	var r regFile
	r.gp[0] = ctx.Rax
	r.gp[1] = ctx.Rcx
	r.gp[2] = ctx.Rdx
	r.gp[3] = ctx.Rbx
	r.gp[4] = ctx.Rsp
	r.gp[5] = ctx.Rbp
	r.gp[6] = ctx.Rsi
	r.gp[7] = ctx.Rdi
	r.gp[8] = ctx.R8
	r.gp[9] = ctx.R9
	r.gp[10] = ctx.R10
	r.gp[11] = ctx.R11
	r.gp[12] = ctx.R12
	r.gp[13] = ctx.R13
	r.gp[14] = ctx.R14
	r.gp[15] = ctx.R15
	r.rip = ctx.Rip
	return r
}

// regFileToCtx writes integer registers from a regFile back into a CONTEXT.
func regFileToCtx(r *regFile, ctx *CONTEXT) {
	ctx.Rax = r.gp[0]
	ctx.Rcx = r.gp[1]
	ctx.Rdx = r.gp[2]
	ctx.Rbx = r.gp[3]
	ctx.Rsp = r.gp[4]
	ctx.Rbp = r.gp[5]
	ctx.Rsi = r.gp[6]
	ctx.Rdi = r.gp[7]
	ctx.R8 = r.gp[8]
	ctx.R9 = r.gp[9]
	ctx.R10 = r.gp[10]
	ctx.R11 = r.gp[11]
	ctx.R12 = r.gp[12]
	ctx.R13 = r.gp[13]
	ctx.R14 = r.gp[14]
	ctx.R15 = r.gp[15]
	ctx.Rip = r.rip
}

// leafUnwind scans up RSP looking for the first stack slot that contains an
// address belonging to a known module. handles leaf frames and frames
// whose RSP doesn't point directly at a return address after unwinding.
func leafUnwind(hProcess uintptr, modules []moduleInfo, r *regFile) bool {
	const maxScan = 256
	rsp := r.gp[4]
	for i := 0; i < maxScan; i++ {
		val, ok := readU64(hProcess, rsp+uint64(i*8))
		if !ok {
			break
		}
		if val == 0 {
			continue
		}
		if findModule(modules, val) != nil {
			r.rip = val
			r.gp[4] = rsp + uint64(i*8) + 8
			return true
		}
	}
	return false
}

// virtualUnwind unwinds one stack frame using unwind tables, falling back to a RSP scan for leaf frames.
func virtualUnwind(hProcess uintptr, modules []moduleInfo, r *regFile) bool {
	pc := r.rip

	mi := findModule(modules, pc)
	if mi == nil {
		return leafUnwind(hProcess, modules, r)
	}

	rf := lookupRuntimeFunction(mi, pc)
	if rf == nil {
		return leafUnwind(hProcess, modules, r)
	}

	return applyUnwindInfo(hProcess, mi, rf, r, pc)
}

// lolololololol
func applyUnwindInfo(hProcess uintptr, mi *moduleInfo, rf *runtimeFunction, r *regFile, pc uint64) bool {
	unwindInfoAddr := mi.base + uint64(rf.UnwindData&^uint32(3))

	for {
		hdr := make([]byte, 4)
		if !readRemote(hProcess, unwindInfoAddr, hdr) {
			return false
		}
		flags := hdr[0] >> 3
		sizeOfProlog := hdr[1]
		countOfCodes := hdr[2]
		frameReg := hdr[3] & 0x0F
		frameOffset := (hdr[3] >> 4) * 16

		codesAddr := unwindInfoAddr + 4
		codeBuf := make([]byte, int(countOfCodes)*2)
		if countOfCodes > 0 {
			if !readRemote(hProcess, codesAddr, codeBuf) {
				return false
			}
		}

		rva := uint32(pc - mi.base)
		prolEnd := rf.BeginAddress + uint32(sizeOfProlog)
		inProlog := rva < prolEnd

		i := 0
		for i < int(countOfCodes) {
			codeOffset := codeBuf[i*2]
			opInfo := codeBuf[i*2+1]
			unwindOp := opInfo & 0x0F
			regNum := (opInfo >> 4) & 0x0F

			if inProlog {
				pcOff := rva - rf.BeginAddress
				if uint32(codeOffset) > pcOff {
					i++
					switch unwindOp {
					case UWOP_ALLOC_LARGE:
						if regNum == 0 {
							i++
						} else {
							i += 2
						}
					case UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128, UWOP_EPILOG:
						i++
					case UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR:
						i += 2
					}
					continue
				}
			}

			i++
			switch unwindOp {
			case UWOP_PUSH_NONVOL:
				val, ok := readU64(hProcess, r.gp[4])
				if !ok {
					return false
				}
				r.gp[regNum] = val
				r.gp[4] += 8

			case UWOP_ALLOC_LARGE:
				if regNum == 0 {
					if i >= int(countOfCodes) {
						return false
					}
					slot := binary.LittleEndian.Uint16(codeBuf[i*2:])
					i++
					r.gp[4] += uint64(slot) * 8
				} else {
					if i+1 >= int(countOfCodes) {
						return false
					}
					lo := uint32(binary.LittleEndian.Uint16(codeBuf[i*2:]))
					hi := uint32(binary.LittleEndian.Uint16(codeBuf[(i+1)*2:]))
					i += 2
					r.gp[4] += uint64(lo | (hi << 16))
				}

			case UWOP_ALLOC_SMALL:
				r.gp[4] += uint64(regNum)*8 + 8

			case UWOP_SET_FPREG:
				r.gp[4] = r.gp[frameReg] - uint64(frameOffset)

			case UWOP_SAVE_NONVOL:
				if i >= int(countOfCodes) {
					return false
				}
				offset := uint64(binary.LittleEndian.Uint16(codeBuf[i*2:])) * 8
				i++
				val, ok := readU64(hProcess, r.gp[4]+offset)
				if !ok {
					return false
				}
				r.gp[regNum] = val

			case UWOP_SAVE_NONVOL_FAR:
				if i+1 >= int(countOfCodes) {
					return false
				}
				lo := uint32(binary.LittleEndian.Uint16(codeBuf[i*2:]))
				hi := uint32(binary.LittleEndian.Uint16(codeBuf[(i+1)*2:]))
				i += 2
				offset := uint64(lo | (hi << 16))
				val, ok := readU64(hProcess, r.gp[4]+offset)
				if !ok {
					return false
				}
				r.gp[regNum] = val

			case UWOP_SAVE_XMM128:
				i++

			case UWOP_SAVE_XMM128_FAR:
				i += 2

			case UWOP_EPILOG:
				i++

			case UWOP_PUSH_MACHFRAME:
				base := r.gp[4]
				if regNum == 1 {
					base += 8
				}
				newRip, ok := readU64(hProcess, base)
				if !ok {
					return false
				}
				newRsp, ok := readU64(hProcess, base+24)
				if !ok {
					return false
				}
				r.rip = newRip
				r.gp[4] = newRsp
				return r.rip != 0
			}
		}

		if flags&UNW_FLAG_CHAININFO != 0 {
			chainOffset := codesAddr + uint64((int(countOfCodes)+1)&^1)*2
			chainBuf := make([]byte, 12)
			if !readRemote(hProcess, chainOffset, chainBuf) {
				return false
			}
			chainRF := runtimeFunction{
				BeginAddress: binary.LittleEndian.Uint32(chainBuf[0:]),
				EndAddress:   binary.LittleEndian.Uint32(chainBuf[4:]),
				UnwindData:   binary.LittleEndian.Uint32(chainBuf[8:]),
			}
			unwindInfoAddr = mi.base + uint64(chainRF.UnwindData&^uint32(3))
			rf = &chainRF
			continue
		}

		break
	}

	retAddr, ok := readU64(hProcess, r.gp[4])
	if !ok || retAddr == 0 {
		return false
	}
	r.rip = retAddr
	r.gp[4] += 8
	return true
}

// findModule returns the moduleInfo that contains pc, or nil.
func findModule(modules []moduleInfo, pc uint64) *moduleInfo {
	for i := range modules {
		m := &modules[i]
		if pc >= m.base && pc < m.base+uint64(m.size) {
			return m
		}
	}
	return nil
}

// resolveAddressNT resolves an address to "module!symbol+offset" using the target's PE export tables.
func resolveAddressNT(hProcess uintptr, modules []moduleInfo, addr uint64) string {
	mi := findModule(modules, addr)
	if mi == nil {
		return fmt.Sprintf("0x%x", addr)
	}

	moduleName := mi.displayName
	rva := uint32(addr - mi.base)

	symName, symRVA := lookupExport(hProcess, mi, rva)
	if symName != "" {
		offset := rva - symRVA
		if offset == 0 {
			return fmt.Sprintf("%s!%s", moduleName, symName)
		}
		return fmt.Sprintf("%s!%s+0x%x", moduleName, symName, offset)
	}

	return fmt.Sprintf("%s+0x%x", moduleName, rva)
}

// lookupExport finds the closest exported name at or before rva in the module's export table.
func lookupExport(hProcess uintptr, mi *moduleInfo, rva uint32) (name string, symRVA uint32) {
	base := mi.base

	elfanew, ok := readU32(hProcess, base+0x3C)
	if !ok {
		return "", 0
	}
	ntHdr := base + uint64(elfanew)
	exportDirRVA, ok := readU32(hProcess, ntHdr+24+0x70)
	if !ok || exportDirRVA == 0 {
		return "", 0
	}

	expBase := base + uint64(exportDirRVA)

	numberOfFunctions, ok := readU32(hProcess, expBase+0x14)
	if !ok || numberOfFunctions == 0 {
		return "", 0
	}
	numberOfNames, ok := readU32(hProcess, expBase+0x18)
	if !ok || numberOfNames == 0 {
		return "", 0
	}
	addressTableRVA, ok := readU32(hProcess, expBase+0x1C)
	if !ok {
		return "", 0
	}
	nameTableRVA, ok := readU32(hProcess, expBase+0x20)
	if !ok {
		return "", 0
	}
	ordinalTableRVA, ok := readU32(hProcess, expBase+0x24)
	if !ok {
		return "", 0
	}

	nameCount := int(numberOfNames)
	namePtrBuf := make([]byte, nameCount*4)
	if !readRemote(hProcess, base+uint64(nameTableRVA), namePtrBuf) {
		return "", 0
	}
	ordinalBuf := make([]byte, nameCount*2)
	if !readRemote(hProcess, base+uint64(ordinalTableRVA), ordinalBuf) {
		return "", 0
	}
	addrCount := int(numberOfFunctions)
	addrBuf := make([]byte, addrCount*4)
	if !readRemote(hProcess, base+uint64(addressTableRVA), addrBuf) {
		return "", 0
	}
	bestName := ""
	bestRVA := uint32(0)
	found := false

	for i := 0; i < nameCount; i++ {
		ord := binary.LittleEndian.Uint16(ordinalBuf[i*2:])
		if int(ord) >= addrCount {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(addrBuf[ord*4:])
		if funcRVA == 0 || funcRVA > rva {
			continue
		}
		if !found || funcRVA > bestRVA {
			bestRVA = funcRVA
			found = true
			nameRVA := binary.LittleEndian.Uint32(namePtrBuf[i*4:])
			bestName = readCStringRemote(hProcess, base+uint64(nameRVA))
		}
	}

	if found {
		return bestName, bestRVA
	}
	return "", 0
}

// readCStringRemote reads a null-terminated ASCII string from the target process.
func readCStringRemote(hProcess uintptr, addr uint64) string {
	var sb strings.Builder
	for i := uint64(0); i < 512; i++ {
		b, ok := readU8(hProcess, addr+i)
		if !ok || b == 0 {
			break
		}
		sb.WriteByte(b)
	}
	return sb.String()
}
