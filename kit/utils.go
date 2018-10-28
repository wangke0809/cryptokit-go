package kit

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"runtime"
	"strings"
	"syscall"
)

func GetPassword() []byte {
	fmt.Print("Enter password: ")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\nConfirm password: ")
	password2, _ := terminal.ReadPassword(int(syscall.Stdin))
	if !validatePassword(password, password2) {
		fmt.Print("\nPasswords do not match. Please try again.\n")
		return GetPassword()
	}
	return password
}

func validatePassword(password1 []byte, password2 []byte) bool {
	if len(password1) == 0 || len(password2) == 0 {
		return false
	}
	if !bytes.Equal(password1, password2) {
		return false
	}
	return true
}

func GetInput(s string) string {
	var input string
	f := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(s)
		input, _ = f.ReadString('\n')
		input = strings.TrimSpace(input)
		if len(input) == 0 {
			continue
		} else {
			return input
		}
	}
}

func GetBasePath(path string) string {
	var i int
	if runtime.GOOS == "windows" {
		i = strings.LastIndex(path, "\\")
	} else {
		i = strings.LastIndex(path, "/")
	}
	path = string(path[0 : i+1])
	return path
}

func GetFileName(path string) string {
	var i int
	if runtime.GOOS == "windows" {
		i = strings.LastIndex(path, "\\")
	} else {
		i = strings.LastIndex(path, "/")
	}
	path = string(path[i+1:])
	return path
}

func CheckErr(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
