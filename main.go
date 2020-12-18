package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/rakyll/statik/fs"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	. "pppoe-sim/pppoe"
	_ "pppoe-sim/statik"
	"runtime"
	"strconv"
	"strings"
)

func printInterfaces(interfaces []*Interface) {
	fmt.Println("当前活动的接口:")
	for i, iface := range interfaces {
		fmt.Printf("%d    %s    %s    %s\n", i+1, iface.HardwareAddr.String(), iface.Name, iface.Description)
	}
}

func installPcap() error {
	statikFS, err := fs.New()
	if err != nil {
		return err
	}
	r, err := statikFS.Open("/npcap.exe")
	if err != nil {
		return err
	}
	defer r.Close()

	tmpfile, err := ioutil.TempFile("", "npcap_*.exe")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name()) // clean up

	_, err = io.Copy(tmpfile, r)
	if err != nil {
		return err
	}
	tmpfile.Close()
	exitCodeStr, err := exec.Command("powershell", fmt.Sprintf("(Start-Process %s -Verb runAs -PassThru -Wait).ExitCode", tmpfile.Name())).Output()
	if err != nil {
		return err
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitCodeStr)))
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return errors.New("non-zero exit code")
	}
	return nil
}

func main() {
	fmt.Println("PPPoE 认证模拟器")
	for {
		fmt.Println()
		interfaces, err := GetActiveInterfaces()
		if err != nil {
			fmt.Printf("ERROR: %s\n", err)
			if runtime.GOOS == "windows" {
				fmt.Println("正在尝试安装 Npcap")
				if err = installPcap(); err != nil {
					log.Fatal(err)
				}
			}
		}
		printInterfaces(interfaces)
		reader := bufio.NewReader(os.Stdin)
		fmt.Println()
		fmt.Print("选择一个接口: ")
		ifIdxStr, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		ifIdx, err := strconv.Atoi(strings.TrimSpace(ifIdxStr))
		if err != nil || ifIdx <= 0 || ifIdx > len(interfaces) {
			continue
		}
		useInterface := interfaces[ifIdx-1]
		fmt.Printf("正在监听接口: (%s) %s\n", useInterface.HardwareAddr, useInterface.Description)
		username, password, err := ServePPPoE(useInterface)
		if err != nil {
			fmt.Println(err)
		}
		if username != "" {
			maxLen := len(username)
			if len(password) > len(username) {
				maxLen = len(password)
			}
			separator := strings.Repeat("=", maxLen+10)
			fmt.Println(separator)
			fmt.Println("PPPoE 认证信息")
			fmt.Println()
			fmt.Printf("用户名: %s\n", username)
			fmt.Printf("密码: %s\n", password)
			fmt.Println(separator)
		}
		fmt.Print("按回车键继续...")
		reader.ReadString('\n')
	}
}
