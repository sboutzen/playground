package hook_keyboard

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	// DLLs
	user32 = windows.NewLazySystemDLL("user32.dll")

	// Functions
	getMessage          = user32.NewProc("GetMessageW")
	setWindowsHookExA   = user32.NewProc("SetWindowsHookExA")
	callNextHookEx      = user32.NewProc("CallNextHookEx")
	unhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")

	// Errors
	ErrUnableToSetHook = errors.New("unable to set hook")
	ErrUnableToUnhook  = errors.New("unable to unhook the hook")
)

const (
	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 256

	// For convenience and clarity
	NULL = 0
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

// HookKeyboard
func HookKeyboard(ctx context.Context, ch chan byte, errorCh chan error) {
	defer syscall.FreeLibrary(syscall.Handle(user32.Handle()))
	var keyboardHook uintptr
	callback := func(aCode int, wParam uintptr, lParam uintptr) uintptr {
		// TODO: Enable caller to determine which events to retrieve
		// TODO: Translate the message properly to support various keyboards / bindings
		if aCode == 0 && wParam == WM_KEYDOWN {
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
	var msg *MSG
	for err := getMesage(msg, 0, 0, 0); err != nil; {
		errorCh <- err

		return
	}

}

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

func setWindowsHook(keyboardHookID int, callback, moduleHandle, threadID uintptr) (hook uintptr, err error) {
	hook, _, winErr := setWindowsHookExA.Call(uintptr(WH_KEYBOARD_LL), callback, moduleHandle, threadID)
	if winErr != windows.ERROR_SUCCESS {
		return NULL, winErr
	}

	if hook == NULL {
		return NULL, ErrUnableToSetHook
	}

	return hook, nil
}

func callNextHook(hook uintptr, aCode int, wParam, lParam uintptr) uintptr {
	returnCode, _, _ := callNextHookEx.Call(hook, uintptr(unsafe.Pointer(&aCode)), wParam, lParam)

	return returnCode
}

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
