package hookie

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	// DLLs
	user32 = windows.NewLazySystemDLL("User32.dll")

	// Functions
	getMessage          = user32.NewProc("GetMessageW")
	translateMessage = user32.NewProc("TranslateMessage")
	dispatchMessage = user32.NewProc("DispatchMessageW")
	translateAcceleratorA = user32.NewProc("TranslateAcceleratorA")
	loadAcceleratorsA = user32.NewProc("LoadAcceleratorsA")
	setWindowsHookExA   = user32.NewProc("SetWindowsHookExA")
	callNextHookEx      = user32.NewProc("CallNextHookEx")
	unhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	getKeyboardLayout = user32.NewProc("GetKeyboardLayout")
	mapVirtualKeyExA = user32.NewProc("MapVirtualKeyExA")
	mapVirtualKeyA = user32.NewProc("MapVirtualKeyA")

	// Errors
	ErrUnableToSetHook = errors.New("unable to set hook")
	ErrUnableToUnhook  = errors.New("unable to unhook the hook")
)

const (
	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 256
	WM_SYSKEYDOWN = 0x0104
	WM_CHAR = 0x0102
	WM_UNICHAR = 0x0109

	// For convenience and clarity
	NULL = 0

	// uMapTypes
	MAPVK_VK_TO_CHAR uintptr = 2
)

// POINT - http://msdn.microsoft.com/en-us/library/windows/desktop/dd162805.aspx
type POINT struct {
	X, Y int32
}

// MSG - https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg
type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

// KBDLLHOOKSTRUCT - docs https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct
type KBDLLHOOKSTRUCT struct {
	vkCode      uint32
	scanCode    uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

func loadAccelerators() {
	//loadAcceleratorsA
}

func translateAccelerator() {
	//translateAcceleratorA
}

func _getKeyboardLayout() (uintptr, error) {
	hkl, _, winErr := getKeyboardLayout.Call(0)
	if winErr != windows.ERROR_SUCCESS {
		return hkl, winErr
	}

	return hkl, nil
}

func mapVirtualKey(hkl uintptr, keyCode uint32) (c uintptr, err error) {
	vkc, _, winErr := mapVirtualKeyExA.Call(uintptr(keyCode), 2, hkl)
	if winErr != windows.ERROR_SUCCESS {
		return c, winErr
	}

	fmt.Printf("rune converted: %c\n", rune(vkc))

	return vkc, nil
}

// HookKeyboard
func HookKeyboard(ctx context.Context, ch chan byte, errorCh chan error) {
	defer syscall.FreeLibrary(syscall.Handle(user32.Handle()))
	var msg *MSG
	var keyboardHook uintptr
	//var hkl uintptr
	callback := func(aCode int, wParam uintptr, lParam uintptr) uintptr {
		// TODO: Enable caller to determine which events to retrieve
		// TODO: Translate the message properly to support various keyboards / bindings
		// || wParam == WM_SYSKEYDOWN || wParam == WM_CHAR || wParam == WM_UNICHAR
		if aCode == 0 && wParam == WM_KEYDOWN {
			//x,a,b := translateMessage.Call(uintptr(unsafe.Pointer(msg)))
			//fmt.Println(x,a,b)
			//x,a,b = dispatchMessage.Call(uintptr(unsafe.Pointer(msg)))
			//fmt.Println(x,a,b)
			kbdstruct := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
			code := byte(kbdstruct.vkCode)
			ch <- code
		}

		return callNextHook(keyboardHook, aCode, wParam, lParam)
	}

	keyboardHook, err := setWindowsHook(WH_KEYBOARD_LL, syscall.NewCallback(callback), 0, 0)
	if err != nil {
		errorCh <- err

		return
	}

	defer unhookWindowsHook(keyboardHook)
	//hkl, err = _getKeyboardLayout()
	//if err != nil {
	//	errorCh <- err
	//}

	for err := getMesage(msg, 0, 0, 0); err != nil; {
		errorCh <- err

		return
	}

}

// getMesage
func getMesage(msg *MSG, hwnd, msgFilterMin, msgFilterMax uintptr) error {
	errCode, _, winErr := getMessage.Call(uintptr(unsafe.Pointer(msg)), hwnd, msgFilterMin, msgFilterMax)
	if winErr != windows.ERROR_SUCCESS {
		return winErr
	}

	if errCode != 0 {
		return windows.Errno(errCode)
	}

	return nil
}

// setWindowsHook registers a hook in the hook chain
func setWindowsHook(keyboardHookID int, callback, moduleHandle, threadID uintptr) (hook uintptr, err error) {
	hook, _, winErr := setWindowsHookExA.Call(uintptr(keyboardHookID), callback, moduleHandle, threadID)
	if winErr != windows.ERROR_SUCCESS {
		return NULL, winErr
	}

	if hook == NULL {
		return NULL, ErrUnableToSetHook
	}

	return hook, nil
}

// callNextHook is called after a hook is executed, allowing the next hook in the hook chain to be called
func callNextHook(hook uintptr, aCode int, wParam, lParam uintptr) uintptr {
	returnCode, _, _ := callNextHookEx.Call(hook, uintptr(unsafe.Pointer(&aCode)), wParam, lParam)

	return returnCode
}

// unhookWindowsHook removes the hook from the hook chain
func unhookWindowsHook(hHook uintptr) error {
	returnCode, _, winErr := unhookWindowsHookEx.Call(hHook)
	if winErr != windows.ERROR_SUCCESS {
		return ErrUnableToUnhook
	}

	if returnCode <= 0 {
		return windows.Errno(returnCode)
	}

	return nil
}
