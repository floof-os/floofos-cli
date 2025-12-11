// FloofOS - Fast Line-rate Offload On Fabric Operating System
// Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License.

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type InterfaceMapping struct {
	VPPName    string
	LinuxName  string
	Speed      string
	TypePrefix string
}

var interfacePrefixes = map[string]struct {
	Prefix string
	Speed  string
}{
	"GigabitEthernet":            {"ge", "1G"},
	"TenGigabitEthernet":         {"xe", "10G"},
	"TwentyFiveGigabitEthernet":  {"tf", "25G"},
	"FortyGigabitEthernet":       {"fo", "40G"},
	"FiftyGigabitEthernet":       {"fi", "50G"},
	"HundredGigabitEthernet":     {"ce", "100G"},
	"TwoHundredGigabitEthernet":  {"cc", "200G"},
	"FourHundredGigabitEthernet": {"cd", "400G"},
}

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

func getVPPInterfaces() []string {
	output, err := exec.Command("vppctl", "show", "interface").Output()
	if err != nil || len(output) == 0 {
		return nil
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")

	ifacePattern := regexp.MustCompile(`^(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigabitEthernet|FortyGigabitEthernet|FiftyGigabitEthernet|HundredGigabitEthernet|TwoHundredGigabitEthernet|FourHundredGigabitEthernet)`)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && ifacePattern.MatchString(fields[0]) {
			interfaces = append(interfaces, fields[0])
		}
	}

	sort.Strings(interfaces)
	return interfaces
}

func getInterfaceType(vppName string) string {
	for prefix := range interfacePrefixes {
		if strings.HasPrefix(vppName, prefix) {
			return prefix
		}
	}
	return "Unknown"
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

func generateMappings(interfaces []string) []InterfaceMapping {
	typeCounters := make(map[string]int)
	var mappings []InterfaceMapping

	for _, iface := range interfaces {
		ifaceType := getInterfaceType(iface)
		if ifaceType == "Unknown" {
			continue
		}

		info := interfacePrefixes[ifaceType]
		idx := typeCounters[ifaceType]
		typeCounters[ifaceType]++

		mappings = append(mappings, InterfaceMapping{
			VPPName:    iface,
			LinuxName:  fmt.Sprintf("%s%d", info.Prefix, idx),
			Speed:      info.Speed,
			TypePrefix: ifaceType,
		})
	}

	return mappings
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

	interfaces := getVPPInterfaces()

	if len(interfaces) == 0 {
		fmt.Println("No network interfaces detected.")
		return nil
	}

	mappings := generateMappings(interfaces)

	fmt.Printf("Detected %d interface(s):\n", len(mappings))
	fmt.Println()

	maxVPPLen := 0
	for _, m := range mappings {
		if len(m.VPPName) > maxVPPLen {
			maxVPPLen = len(m.VPPName)
		}
	}

	for _, m := range mappings {
		fmt.Printf("  %-*s  ->  %-6s  (%s)\n", maxVPPLen, m.VPPName, m.LinuxName, m.Speed)
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
		fmt.Printf("Configuring %s... ", m.LinuxName)

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
