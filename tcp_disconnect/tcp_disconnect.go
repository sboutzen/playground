package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/sboutzen/playground/hookie"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

var (
	// Load the libraries needed
	psapi    = windows.NewLazySystemDLL("psapi.dll")
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
	//kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// Link the functions in those libraries so we can call them.
	getTcpTable2             = iphlpapi.NewProc("GetTcpTable2")
	setTcpEntry              = iphlpapi.NewProc("SetTcpEntry")
	enumProcesses            = psapi.NewProc("EnumProcesses")
	enumProcessModules       = psapi.NewProc("EnumProcessModules")
	getModuleBaseName        = psapi.NewProc("GetModuleBaseNameA")
	getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	enumWindows              = user32.NewProc("EnumWindows")
	//getModuleHandleA         = kernel32.NewProc("GetModuleHandleA")

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
	WH_KEYBOARD_LL           = 13
	WH_KEYBOARD              = 2
	WM_KEYDOWN               = 256
	WM_SYSKEYDOWN            = 260
	WM_KEYUP                 = 257
	WM_SYSKEYUP              = 261
	WM_KEYFIRST              = 256
	WM_KEYLAST               = 264
	PM_NOREMOVE              = 0x000
	PM_REMOVE                = 0x001
	PM_NOYIELD               = 0x002
	WM_LBUTTONDOWN           = 513
	WM_RBUTTONDOWN           = 516
	NULL                     = 0
)

// MIB_TCPROW2 - https://docs.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow2
type MIB_TCPROW2 struct {
	dwState        uint32
	dwLocalAddr    uint32
	dwLocalPort    uint32
	dwRemoteAddr   uint32
	dwRemotePort   uint32
	dwOwningPid    uint32
	dwOffloadState uint32
}

// MIB_TCPTABLE2 - https://docs.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable2
type MIB_TCPTABLE2 struct {
	dwNumEntries uint32
	table        [ANY_SIZE]MIB_TCPROW2
}

// GetTcpTable2 returns a map from a PID to a TCP connection
func GetTcpTable2() (map[uint32]MIB_TCPROW2, error) {
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

// EnumProcesses returns an array of currently active processIDs
func EnumProcesses() ([]uint32, error) {
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

func EnumProcessModules(processHandle syscall.Handle) (moduleHandles []uint64, bytesNeeded uint32, err error) {
	// Enumerate the process modules, giving us a module handle
	hModules := make([]uint64, 1024)
	var hModuleSize uint32
	var lpcbNeeded uint32
	winErrCode, _, winErr := enumProcessModules.Call(uintptr(processHandle), uintptr(unsafe.Pointer(&hModules[0])), uintptr(unsafe.Pointer(&hModuleSize)), uintptr(unsafe.Pointer(&lpcbNeeded)))
	if winErr != windows.ERROR_SUCCESS {
		return nil, 0, winErr
	}

	if winErrCode == 0 {
		return nil, 0, ErrEnumProcessModulesFailed
	}

	return hModules, lpcbNeeded, nil
}

func GetModuleBaseName(processHandle syscall.Handle, moduleHandle uint64, nameBuffer []byte, nameBufferSize int) (moduleName string, err error) {
	// For getModuleBaseName, the return value indicates bytes written to the buffer. If the value is 0, an error occurred
	bytesWritten, _, err := getModuleBaseName.Call(uintptr(processHandle), uintptr(moduleHandle), uintptr(unsafe.Pointer(&nameBuffer[0])), uintptr(unsafe.Pointer(&nameBufferSize)))
	if err != windows.ERROR_SUCCESS {
		return moduleName, err
	}

	if bytesWritten == 0 {
		return moduleName, ErrGetModuleBaseNameFailed
	}

	str := string(nameBuffer[:bytesWritten])

	return str, nil
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
		hModules, lpcbNeeded, err := EnumProcessModules(hProcess)
		if err != nil {
			panic(err)
		}

		lpBaseNameSize := 1024 // Doesnt seem like this size matters for the function call, but we do it anyways
		lpBaseName := make([]byte, lpBaseNameSize)
		for i := 0; i < int(lpcbNeeded/LPDWORD_SIZE); i++ {
			mh := hModules[i]

			str, err := GetModuleBaseName(hProcess, mh, lpBaseName, lpBaseNameSize)
			if err != nil {
				panic(err)
			}

			if strings.Contains(strings.ToLower(str), "exile") {
				//a1, b2, c3 := getModuleHandleA.Call(0)
				//fmt.Println(a1, b2, c3)

				return p, nil
			}
		}
	}

	return 0, ErrTargetPIDNotFound
}

func SetTcpEntry(mib MIB_TCPROW2) error {
	windowsErrorCode, _, err := setTcpEntry.Call(uintptr(unsafe.Pointer(&mib)))
	if err != windows.ERROR_SUCCESS {
		return err
	}

	if windowsErrorCode != 0 {
		return windows.Errno(windowsErrorCode)
	}

	return nil
}

func getWindowHandleForPID(targetPID uint32) (syscall.Handle, error) {
	var hwnd syscall.Handle
	var err error
	callback := syscall.NewCallback(func(h syscall.Handle) uintptr {
		var pid uint32
		var c bool
		_, _, winErr := getWindowThreadProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
		if winErr != windows.ERROR_SUCCESS {
			err = winErr
			c = true

			// If an error occurs, we stop the enumeration
			return uintptr(unsafe.Pointer(&c))
		}

		// TODO: Why is this if hit multiple times even though i return true? It seems like my boolean return is actually ignored
		// EDIT: Processes can have multiple window handles, and for whatever reason, it seems PoE has 3
		if pid == targetPID {
			hwnd = h
			c = true

			// If we find the window, we stop the enumeration
			return uintptr(unsafe.Pointer(&c))
		}

		// If we dont find it, we keep looking
		c = false

		return uintptr(unsafe.Pointer(&c))
	})

	winCode, _, winErr := enumWindows.Call(callback, 0)
	if winErr != windows.ERROR_SUCCESS {
		return hwnd, winErr
	}

	if winCode != 0 {
		return hwnd, windows.Errno(winCode)
	}

	return hwnd, nil
}

func getPoeConnection() (MIB_TCPROW2, error) {
	var connection MIB_TCPROW2
	tcpConnections, err := GetTcpTable2()
	if err != nil {
		return connection, err
	}

	PIDs, err := EnumProcesses()
	if err != nil {
		return connection, err
	}

	targetPID, err := getTargetPID(PIDs)
	if err != nil {
		return connection, err
	}

	mib, ok := tcpConnections[targetPID]
	if !ok {
		return connection, ErrTargetConnectionNotFound
	}

	return mib, err
}

func waitForPoeConnection() (MIB_TCPROW2, error) {
	var empty MIB_TCPROW2
	for {
		con, err := getPoeConnection()
		if err != nil && err != ErrTargetConnectionNotFound {
			return empty, err
		}

		if err == nil {
			return con, nil
		}
	}
}

func start() {
	defer syscall.FreeLibrary(syscall.Handle(user32.Handle()))
	defer syscall.FreeLibrary(syscall.Handle(iphlpapi.Handle()))
	defer syscall.FreeLibrary(syscall.Handle(psapi.Handle()))

	//windowHandle, err := getWindowHandleForPID(13652)
	//fmt.Println(windowHandle, err)
	ctx := context.Background()
	ch := make(chan byte)
	errorCh := make(chan error, 10)
	go hookie.HookKeyboard(ctx, ch, errorCh)

	// The main loop
	for {
		select {
		case c := <- ch:
			if string(c) == "Q" {
				//Kill the target connection
				poeConnection, err := waitForPoeConnection()
				if err != nil {
					panic(err)
				}

				poeConnection.dwState = MIB_TCP_STATE_DELETE_TCB
				err = SetTcpEntry(poeConnection)

				// For some reason, when you tcp disconnect POE, they will open one connection, then shortly after open a new one and close the other one.
				// This means that if we get the current connection too fast, we risk getting the connection that is already closed.
				//time.Sleep(5 * time.Second) // TODO: Find a better way to handle this problem

				//if err == windows.ERROR_MR_MID_NOT_FOUND {
				if err != nil {
					fmt.Printf("SetTcpEntry failed: %v\n", err)
				}
			}
		}
	}
}

func main() {
	// TODO: Ask for elevation if rights are not admin
	// TODO: Enable killing various processes by name, specified either as a flag or through a gui
	// TODO: Enable choosing key combination for killing the connections, either as a flag or through a gui (maybe fyne or gio gui)
	// TODO: Enable monitoring the PoE process so that we can know when it opens a new connection and always be ready to instantly close it.

	start()

	defer func() {
		if r := recover(); r != nil {
			panic(r.(error))
		}
	}()
}
