package main

import (
	"fmt"
	"os"
	"unsafe"

	wincall "github.com/carved4/go-wincall"
	"github.com/spf13/cobra"
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010

	OBJ_INHERIT          = 0x00000002
	OBJ_CASE_INSENSITIVE = 0x00000040
)

// stacktrace opens the target process, enumerates its modules, and traces each requested thread.
func stacktrace(pid, tid uint32) {
	targetTids := collectThreads(pid, tid)

	cid := CLIENT_ID{UniqueProcess: uintptr(pid)}
	oa := newObjectAttributes()
	var hProcess uintptr
	status, _ := wincall.IndirectSyscall(sc.ntOpenProcess.ssn, sc.ntOpenProcess.addr,
		uintptr(unsafe.Pointer(&hProcess)),
		uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	if status != 0 {
		fmt.Fprintf(os.Stderr, "[!] NtOpenProcess failed for PID %d (status 0x%x)\n", pid, uint32(status))
		return
	}
	defer wincall.IndirectSyscall(sc.ntClose.ssn, sc.ntClose.addr, hProcess)

	modules := enumModules(hProcess)

	for _, t := range targetTids {
		traceThreadStack(pid, hProcess, modules, t)
	}
}

func main() {
	initSyscalls()
	var pid uint32
	var tid uint32
	var procName string

	root := &cobra.Command{
		Use:   "trace",
		Short: "print the stack trace of a process or thread",
		Long:  "\n\na go program to print the stack trace of a given thread",
		RunE: func(cmd *cobra.Command, args []string) error {
			if procName != "" {
				resolved, err := findPidByName(procName)
				if err != nil {
					return err
				}
				pid = resolved
			}
			if pid == 0 {
				return fmt.Errorf("must provide --pid or --name")
			}
			if pid == uint32(os.Getpid()) {
				return fmt.Errorf("do not run this program against the current process")
			}
			stacktrace(pid, tid)
			return nil
		},
	}

	root.Flags().Uint32Var(&pid, "pid", 0, "process id")
	root.Flags().Uint32Var(&tid, "tid", 0, "thread id (0 = all threads)")
	root.Flags().StringVar(&procName, "name", "", "process name (e.g. notepad.exe); resolved via NtQuerySystemInformation")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
