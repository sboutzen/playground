package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

var (
	// Load the libraries needed
	psapi    = windows.NewLazySystemDLL("psapi.dll")
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// Link the functions in those libraries so we can call them.
	getTcpTable2       = iphlpapi.NewProc("GetTcpTable2")
	setTcpEntry        = iphlpapi.NewProc("SetTcpEntry")
	enumProcesses      = psapi.NewProc("EnumProcesses")
	enumProcessModules = psapi.NewProc("EnumProcessModules")
	getModuleBaseName  = psapi.NewProc("GetModuleBaseNameA")

	// Errors
	ErrEnumProcessesFailed      = errors.New("an error occurred when calling enumProcesses")
	ErrEnumProcessModulesFailed = errors.New("an error occurred when calling enumProcessModules")
	ErrGetModuleBaseNameFailed  = errors.New("an error occurred when calling getModuleBaseName")
	ErrTargetPIDNotFound        = errors.New("unable to find target PID")
	ErrTargetConnectionNotFound = errors.New("unable to find target connection")

	// Sizes
	LPDWORD_SIZE = uint32(unsafe.Sizeof(uint64(0)))
)

const (
	PROCESS_VM_READ          = 0x00000010
	PROCESS_DUP_HANDLE       = 0x00000040
	ANY_SIZE                 = 1
	ORDER                    = 1
	MIB_TCP_STATE_DELETE_TCB = 12
)

type MIB_TCPROW2 struct {
	dwState        uint32
	dwLocalAddr    uint32
	dwLocalPort    uint32
	dwRemoteAddr   uint32
	dwRemotePort   uint32
	dwOwningPid    uint32
	dwOffloadState uint32
}

type MIB_TCPTABLE2 struct {
	dwNumEntries uint32
	table        [ANY_SIZE]MIB_TCPROW2
}

// getTcpTable returns a map from a PID to a TCP connection
func getTcpTable() (map[uint32]MIB_TCPROW2, error) {
	// First we checkout how many entries exist, this will throw an error
	// If the error is ERROR_INSUFFICIENT_BUFFER, the `size` will now be he required number of bytes needed
	var size uint32
	var buf []byte
	var tcpTable *MIB_TCPTABLE2
	err, _, _ := getTcpTable2.Call(uintptr(unsafe.Pointer(tcpTable)), uintptr(unsafe.Pointer(&size)), ORDER)
	if winErr := windows.Errno(err); winErr != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, winErr
	}

	// Now that we know the size, fetch all the entries
	buf = make([]byte, size)
	tblp := (*MIB_TCPTABLE2)(unsafe.Pointer(&buf[0]))
	err, _, _ = getTcpTable2.Call(uintptr(unsafe.Pointer(tblp)), uintptr(unsafe.Pointer(&size)), ORDER)
	if winErr := windows.Errno(err); winErr != windows.ERROR_SUCCESS {
		return nil, winErr
	}

	// Build the map where we lookup connections
	connections := make(map[uint32]MIB_TCPROW2, tblp.dwNumEntries)
	idx := int(unsafe.Sizeof(tblp.dwNumEntries))
	step := int(unsafe.Sizeof(tblp.table))
	for i := 0; uint32(i) < tblp.dwNumEntries; i++ {
		mibs := *(*MIB_TCPROW2)(unsafe.Pointer(&buf[idx]))
		connections[mibs.dwOwningPid] = mibs
		idx += step
	}

	return connections, nil
}

// getPIDs returns an array of processIDs
func getPIDs() ([]uint32, error) {
	lpidProcess := make([]uint32, 10000)
	var cb uint32
	var lpcbNeeded uint64 // We ignore the number of bytes returned
	winCode, _, winErr := enumProcesses.Call(uintptr(unsafe.Pointer(&lpidProcess[0])), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&lpcbNeeded)))
	if winCode == 0 {
		return nil, ErrEnumProcessesFailed
	}

	if winErr != windows.ERROR_SUCCESS {
		return nil, winErr
	}

	return lpidProcess, nil
}

func getTargetPID(PIDs []uint32) (uint32, error) {
	// For each process id fetch the name of the process
	for _, p := range PIDs {
		if p == 0 {
			continue
		}

		// Fetch a process handle
		hProcess, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_DUP_HANDLE, false, p)
		if err == syscall.ERROR_ACCESS_DENIED { // Some processes dont allow to open the process.
			continue
		}

		if err != nil {
			return 0, err
		}

		// Enumerate the process modules, giving us a module handle
		hModules := make([]uint64, 1024)
		var hModuleSize uint32
		var lpcbNeeded uint32
		winErrCode, _, winErr := enumProcessModules.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&hModules[0])), uintptr(unsafe.Pointer(&hModuleSize)), uintptr(unsafe.Pointer(&lpcbNeeded)))
		if winErr != windows.ERROR_SUCCESS {
			return 0, winErr
		}

		if winErrCode == 0 {
			return 0, ErrEnumProcessModulesFailed
		}

		lpBaseName := make([]byte, 500)
		for i := 0; i < int(lpcbNeeded/LPDWORD_SIZE); i++ {
			mh := hModules[i]

			// For getModuleBaseName, the return value indicates bytes written to the buffer. If the value is 0, an error occurred
			bytesWritten, _, err := getModuleBaseName.Call(uintptr(hProcess), uintptr(mh), uintptr(unsafe.Pointer(&lpBaseName[0])), 10000)
			if err != windows.ERROR_SUCCESS {
				return 0, err
			}

			if bytesWritten == 0 {
				return 0, ErrGetModuleBaseNameFailed
			}

			str := string(lpBaseName[:bytesWritten])
			if strings.Contains(strings.ToLower(str), "exile") {
				return p, nil
			}
		}
	}

	return 0, ErrTargetPIDNotFound
}

func killTargetConnection(mib MIB_TCPROW2) error {
	connection := mib
	connection.dwState = MIB_TCP_STATE_DELETE_TCB
	windowsErrorCode, _, err := setTcpEntry.Call(uintptr(unsafe.Pointer(&connection)))
	if err != windows.ERROR_SUCCESS {
		return err
	}

	if windowsErrorCode != 0 {
		return windows.Errno(windowsErrorCode)
	}

	return nil
}

func main() {
	// TODO: Ask for elevation if rights are not admin
	// TODO: Enable killing various processes by name, specified either as a flag or through a gui
	// TODO: Enable choosing key combination for killing the connections, either as a flag or through a gui
	// TODO: Monitor the process so we catch it when it creates a new connection after being killed
	// TODO: Monitor the target process so that if it terminates, and is started again, we find it
	tcpConnections, err := getTcpTable()
	if err != nil {
		panic(err)
	}

	PIDs, err := getPIDs()
	if err != nil {
		panic(err)
	}

	targetPID, err := getTargetPID(PIDs)
	if err != nil {
		panic(err)
	}

	mib, ok := tcpConnections[targetPID]
	if !ok {
		panic(ErrTargetConnectionNotFound)
	}

	err = killTargetConnection(mib)
	if err != nil {
		panic(err)
	}
}
