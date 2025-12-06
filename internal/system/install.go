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
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type InstallConfig struct {
	TargetDisk     string
	Hostname       string
	Password       string
	UseEntireDisk  bool
	ConsoleType    string
	PreserveConfig bool
	ConfigCommit   int
}

func promptInput(prompt string, defaultVal string) string {
	fmt.Print(prompt)

	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err == nil {
		term.Restore(int(syscall.Stdin), oldState)
	}

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultVal
	}
	return input
}

func listConfigCommits() []int {
	var commits []int
	configDir := "/etc/floofos-config/commits"

	entries, err := os.ReadDir(configDir)
	if err != nil {
		return commits
	}

	for _, entry := range entries {
		if entry.IsDir() {
			num, err := strconv.Atoi(entry.Name())
			if err == nil {
				commits = append(commits, num)
			}
		}
	}

	sort.Ints(commits)
	return commits
}

func getCommitComment(commitNum int) string {
	commentFile := fmt.Sprintf("/etc/floofos-config/commits/%d/.comment", commitNum)
	data, err := os.ReadFile(commentFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func RunInstall() error {
	fmt.Println()
	fmt.Println("FloofOS System Installation")
	fmt.Println()
	fmt.Println("This command will install FloofOS to permanent storage.")
	fmt.Println("All existing data on the target disk will be erased.")
	fmt.Println()

	confirm := promptInput("Would you like to continue? [y/N]: ", "n")
	if confirm != "y" && confirm != "Y" && confirm != "yes" {
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
		input := promptInput(fmt.Sprintf("Which disk should be used for installation? (Default: %s): ", disks[0].Path), "")
		if input == "" {
			targetDisk = disks[0].Path
		} else {
			targetDisk = input
		}
	} else {
		input := promptInput("Which disk should be used for installation? [1]: ", "1")
		idx := 0
		fmt.Sscanf(input, "%d", &idx)
		if idx < 1 || idx > len(disks) {
			idx = 1
		}
		targetDisk = disks[idx-1].Path
	}

	fmt.Println()
	confirm = promptInput("Installation will delete all data on the drive. Continue? [y/N]: ", "n")
	if confirm != "y" && confirm != "Y" && confirm != "yes" {
		fmt.Println("Installation aborted.")
		return nil
	}

	fmt.Println()
	promptInput("Would you like to use all the free space on the drive? [Y/n]: ", "y")

	fmt.Println()
	consoleInput := promptInput("What console should be used by default? (K: KVM, S: Serial) [K]: ", "K")
	consoleInput = strings.ToUpper(consoleInput)
	consoleType := "kvm"
	if consoleInput == "S" {
		consoleType = "serial"
	}

	currentHostname, _ := os.Hostname()
	fmt.Println()
	hostname := promptInput(fmt.Sprintf("What is the hostname of this system? [%s]: ", currentHostname), currentHostname)

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

	preserveConfig := false
	configCommit := -1

	commits := listConfigCommits()
	if len(commits) > 0 {
		fmt.Println()
		fmt.Println("Configuration found in floofos-config:")
		fmt.Println()

		displayCount := 10
		if len(commits) < displayCount {
			displayCount = len(commits)
		}

		for i := 0; i < displayCount; i++ {
			num := commits[i]
			comment := getCommitComment(num)
			if comment != "" {
				fmt.Printf("  %d: commit %d - %s\n", i+1, num, comment)
			} else {
				fmt.Printf("  %d: commit %d\n", i+1, num)
			}
		}

		if len(commits) > 10 {
			fmt.Printf("  ... and %d more commits\n", len(commits)-10)
		}
		fmt.Println()

		preserveInput := promptInput("Would you like to preserve configuration? [Y/n]: ", "y")
		if preserveInput != "n" && preserveInput != "N" && preserveInput != "no" {
			preserveConfig = true

			if len(commits) == 1 {
				configCommit = commits[0]
				fmt.Printf("Using configuration: commit %d\n", configCommit)
			} else {
				fmt.Println()
				selectInput := promptInput(fmt.Sprintf("Which configuration to restore? [1] (commit %d): ", commits[0]), "1")
				idx := 0
				fmt.Sscanf(selectInput, "%d", &idx)
				if idx < 1 || idx > len(commits) {
					idx = 1
				}
				configCommit = commits[idx-1]
			}
		}
	}

	fmt.Println()
	fmt.Println("Installation summary:")
	fmt.Println()
	fmt.Printf("  Target disk     : %s\n", targetDisk)
	fmt.Printf("  Hostname        : %s\n", hostname)
	fmt.Printf("  Console         : %s\n", consoleType)
	fmt.Printf("  User            : floofos\n")
	if preserveConfig && configCommit >= 0 {
		comment := getCommitComment(configCommit)
		if comment != "" {
			fmt.Printf("  Config restore  : commit %d (%s)\n", configCommit, comment)
		} else {
			fmt.Printf("  Config restore  : commit %d\n", configCommit)
		}
	}
	fmt.Println()

	confirm = promptInput("Proceed with installation? [y/N]: ", "n")
	if confirm != "y" && confirm != "Y" && confirm != "yes" {
		fmt.Println("Installation aborted.")
		return nil
	}

	fmt.Println()
	fmt.Println("Creating partition table...")

	preserveArg := "false"
	if preserveConfig {
		preserveArg = "true"
	}

	cmd := exec.Command("/usr/local/sbin/floofos-install",
		"--disk", targetDisk,
		"--hostname", hostname,
		"--console", consoleType,
		"--password", string(password1),
		"--preserve-config", preserveArg,
		"--config-commit", strconv.Itoa(configCommit),
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
	if preserveConfig {
		fmt.Println("Your configuration has been preserved and will be restored on first boot.")
	}
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
