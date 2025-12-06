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
	"strings"
	"syscall"

	"golang.org/x/term"
)

type InstallConfig struct {
	TargetDisk    string
	Hostname      string
	Password      string
	UseEntireDisk bool
	ConsoleType   string
}

func RunInstall() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("FloofOS System Installation")
	fmt.Println()
	fmt.Println("This command will install FloofOS to permanent storage.")
	fmt.Println("All existing data on the target disk will be erased.")
	fmt.Println()

	fmt.Print("Would you like to continue? [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Installation aborted.")
		return nil
	}
	fmt.Println()

	fmt.Println("Probing disks...")
	disks, err := detectDisks()
	if err != nil {
		return fmt.Errorf("failed to detect disks: %v", err)
	}

	if len(disks) == 0 {
		return fmt.Errorf("no suitable disks found")
	}

	fmt.Printf("%d disk(s) found\n", len(disks))
	fmt.Println()
	fmt.Println("The following disks were found:")
	for i, disk := range disks {
		fmt.Printf("  %d: %s\n", i+1, disk)
	}
	fmt.Println()

	var targetDisk string
	if len(disks) == 1 {
		fmt.Printf("Which disk should be used for installation? (Default: %s): ", disks[0].Path)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			targetDisk = disks[0].Path
		} else {
			targetDisk = input
		}
	} else {
		fmt.Print("Which disk should be used for installation? [1]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			targetDisk = disks[0].Path
		} else {
			idx := 0
			fmt.Sscanf(input, "%d", &idx)
			if idx < 1 || idx > len(disks) {
				return fmt.Errorf("invalid disk selection")
			}
			targetDisk = disks[idx-1].Path
		}
	}

	fmt.Println()
	fmt.Println("Installation will delete all data on the drive. Continue? [y/N]: ")
	confirm, _ = reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Installation aborted.")
		return nil
	}

	fmt.Println()
	fmt.Print("Would you like to use all the free space on the drive? [Y/n]: ")
	_, _ = reader.ReadString('\n')

	fmt.Println()
	fmt.Print("What console should be used by default? (K: KVM, S: Serial) (Default: K): ")
	consoleInput, _ := reader.ReadString('\n')
	consoleInput = strings.TrimSpace(strings.ToUpper(consoleInput))
	consoleType := "kvm"
	if consoleInput == "S" {
		consoleType = "serial"
	}

	currentHostname, _ := os.Hostname()
	fmt.Println()
	fmt.Printf("What is the hostname of this system? [%s]: ", currentHostname)
	hostname, _ := reader.ReadString('\n')
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = currentHostname
	}

	fmt.Println()
	fmt.Print("Please enter a password for the 'floofos' user: ")
	password1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	fmt.Print("Please confirm the password: ")
	password2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	if string(password1) != string(password2) {
		return fmt.Errorf("passwords do not match")
	}

	if len(password1) < 4 {
		return fmt.Errorf("password must be at least 4 characters")
	}

	fmt.Println()
	fmt.Println("Installation summary:")
	fmt.Println()
	fmt.Printf("  Target disk : %s\n", targetDisk)
	fmt.Printf("  Hostname    : %s\n", hostname)
	fmt.Printf("  Console     : %s\n", consoleType)
	fmt.Printf("  User        : floofos\n")
	fmt.Println()

	fmt.Print("Proceed with installation? [y/N]: ")
	confirm, _ = reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Installation aborted.")
		return nil
	}

	fmt.Println()
	fmt.Println("Creating partition table...")

	cmd := exec.Command("/usr/local/sbin/floofos-install",
		"--disk", targetDisk,
		"--hostname", hostname,
		"--console", consoleType,
		"--password", string(password1),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("installation failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Installation complete.")
	fmt.Println()
	fmt.Println("Remove the installation media and reboot the system.")
	fmt.Println("To reboot now, type: reboot")
	fmt.Println()

	return nil
}

type DiskInfo struct {
	Path  string
	Size  string
	Model string
}

func (d DiskInfo) String() string {
	if d.Model == "Unknown" || d.Model == "" {
		return fmt.Sprintf("Drive: %s (%s)", d.Path, d.Size)
	}
	return fmt.Sprintf("Drive: %s (%s) %s", d.Path, d.Size, d.Model)
}

func detectDisks() ([]DiskInfo, error) {
	var disks []DiskInfo

	cmd := exec.Command("lsblk", "-d", "-n", "-o", "NAME,SIZE,MODEL", "-e", "7,11")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := fields[0]
			size := fields[1]
			model := ""
			if len(fields) >= 3 {
				model = strings.Join(fields[2:], " ")
			}

			if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
				continue
			}

			if strings.HasPrefix(name, "sr") {
				continue
			}

			disks = append(disks, DiskInfo{
				Path:  "/dev/" + name,
				Size:  size,
				Model: model,
			})
		}
	}

	return disks, nil
}
