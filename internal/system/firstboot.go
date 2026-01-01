// FloofOS - Fast Line-rate Offload On Fabric Operating System
// Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License.

package system

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type InterfaceMapping struct {
	PCI       string `json:"pci"`
	VPPName   string `json:"vpp_name"`
	LinuxName string `json:"linux_name"`
	Speed     int    `json:"speed"`
	NUMA      int    `json:"numa"`
	CardID    int    `json:"card_id"`
	PortIdx   int    `json:"port_idx"`
	Workers   string `json:"workers"`
}

type InterfaceMapFile struct {
	Generated  string             `json:"generated"`
	Interfaces []InterfaceMapping `json:"interfaces"`
}

const interfaceMapPath = "/etc/vpp/interface-map.json"

func IsFirstBoot() bool {
	configFile := "/etc/vpp/config/vppcfg.vpp"

	data, err := os.ReadFile(configFile)
	if err != nil {
		return true
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return true
	}

	if strings.Contains(content, "lcp create") {
		return false
	}

	return true
}

func waitVPPReady() bool {
	for i := 0; i < 30; i++ {
		cmd := exec.Command("vppctl", "show", "version")
		if err := cmd.Run(); err == nil {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func loadInterfaceMap() ([]InterfaceMapping, error) {
	data, err := os.ReadFile(interfaceMapPath)
	if err != nil {
		return nil, err
	}

	var mapFile InterfaceMapFile
	if err := json.Unmarshal(data, &mapFile); err != nil {
		return nil, err
	}

	return mapFile.Interfaces, nil
}

func getVPPInterfaces() []string {
	output, err := exec.Command("vppctl", "show", "interface").Output()
	if err != nil || len(output) == 0 {
		return nil
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")

	ifacePattern := regexp.MustCompile(`^(\d+\.?\d*GE\d+/\d+/\d+|GE\d+/\d+/\d+)`)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && ifacePattern.MatchString(fields[0]) {
			interfaces = append(interfaces, fields[0])
		}
	}

	sort.Strings(interfaces)
	return interfaces
}

func speedToString(speed int) string {
	switch {
	case speed >= 400000:
		return "400G"
	case speed >= 200000:
		return "200G"
	case speed >= 100000:
		return "100G"
	case speed >= 50000:
		return "50G"
	case speed >= 40000:
		return "40G"
	case speed >= 25000:
		return "25G"
	case speed >= 10000:
		return "10G"
	case speed >= 2500:
		return "2.5G"
	default:
		return "1G"
	}
}

func promptFirstBootInput(prompt string, defaultVal string) string {
	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultVal
	}
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultVal
	}
	return input
}

func RunFirstBootSetup() error {
	if !IsFirstBoot() {
		return nil
	}

	fmt.Println()
	fmt.Println("Waiting for VPP...")

	if !waitVPPReady() {
		fmt.Println("VPP not ready, skipping interface setup")
		return nil
	}

	time.Sleep(2 * time.Second)

	fmt.Println()
	fmt.Println("Initial interface setup")
	fmt.Println()

	mappings, err := loadInterfaceMap()
	if err != nil {
		interfaces := getVPPInterfaces()
		if len(interfaces) == 0 {
			fmt.Println("No network interfaces detected.")
			return nil
		}

		fmt.Printf("Detected %d interface(s):\n", len(interfaces))
		fmt.Println()

		for _, iface := range interfaces {
			fmt.Printf("  %s\n", iface)
		}
		fmt.Println()

		confirm := promptFirstBootInput("Configure interfaces? [Y/n]: ", "y")
		if confirm == "n" || confirm == "N" || confirm == "no" {
			fmt.Println()
			fmt.Println("Skipped. Configure manually with: lcp create <interface> host-if <name>")
			return nil
		}

		fmt.Println()

		success := 0
		failed := 0

		for i, iface := range interfaces {
			linuxName := fmt.Sprintf("eth%d", i)
			fmt.Printf("Configuring %s -> %s... ", iface, linuxName)

			cmd := exec.Command("vppctl", "lcp", "create", iface, "host-if", linuxName)
			err := cmd.Run()
			if err != nil {
				fmt.Println("failed")
				failed++
				continue
			}

			cmd = exec.Command("vppctl", "set", "interface", "state", iface, "up")
			cmd.Run()

			time.Sleep(100 * time.Millisecond)
			fmt.Println("done")
			success++
		}

		fmt.Println()
		if failed > 0 {
			fmt.Printf("Configured %d interface(s), %d failed\n", success, failed)
		} else {
			fmt.Printf("Configured %d interface(s)\n", success)
		}
		fmt.Println()
		fmt.Println("Enter 'configure' mode and type 'commit' to save configuration")
		fmt.Println()

		return nil
	}

	if len(mappings) == 0 {
		fmt.Println("No network interfaces detected.")
		return nil
	}

	fmt.Printf("Detected %d interface(s):\n", len(mappings))
	fmt.Println()

	maxVPPLen := 0
	maxLinuxLen := 0
	for _, m := range mappings {
		if len(m.VPPName) > maxVPPLen {
			maxVPPLen = len(m.VPPName)
		}
		if len(m.LinuxName) > maxLinuxLen {
			maxLinuxLen = len(m.LinuxName)
		}
	}

	for _, m := range mappings {
		speedStr := speedToString(m.Speed)
		numaStr := ""
		if m.NUMA > 0 {
			numaStr = fmt.Sprintf(" NUMA%d", m.NUMA)
		}
		fmt.Printf("  %-*s  ->  %-*s  (%s%s)\n", maxVPPLen, m.VPPName, maxLinuxLen, m.LinuxName, speedStr, numaStr)
	}
	fmt.Println()

	confirm := promptFirstBootInput("Configure interfaces? [Y/n]: ", "y")
	if confirm == "n" || confirm == "N" || confirm == "no" {
		fmt.Println()
		fmt.Println("Skipped. Configure manually with: lcp create <interface> host-if <name>")
		return nil
	}

	fmt.Println()

	success := 0
	failed := 0

	for _, m := range mappings {
		fmt.Printf("Configuring %s -> %s... ", m.VPPName, m.LinuxName)

		cmd := exec.Command("vppctl", "lcp", "create", m.VPPName, "host-if", m.LinuxName)
		err := cmd.Run()
		if err != nil {
			fmt.Println("failed")
			failed++
			continue
		}

		cmd = exec.Command("vppctl", "set", "interface", "state", m.VPPName, "up")
		cmd.Run()

		time.Sleep(100 * time.Millisecond)
		fmt.Println("done")
		success++
	}

	fmt.Println()
	if failed > 0 {
		fmt.Printf("Configured %d interface(s), %d failed\n", success, failed)
	} else {
		fmt.Printf("Configured %d interface(s)\n", success)
	}
	fmt.Println()
	fmt.Println("Enter 'configure' mode and type 'commit' to save configuration")
	fmt.Println()

	return nil
}
