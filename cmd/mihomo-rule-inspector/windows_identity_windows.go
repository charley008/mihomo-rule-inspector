//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func initWindowsShellIdentity() {
	appID := windows.StringToUTF16Ptr("MetaCubeX.MihomoRuleInspector")
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	proc := shell32.NewProc("SetCurrentProcessExplicitAppUserModelID")
	if err := shell32.Load(); err != nil {
		return
	}
	_, _, _ = proc.Call(uintptr(unsafe.Pointer(appID)))
}
