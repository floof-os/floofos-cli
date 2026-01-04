/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/floof-os/floofos-cli/internal/bird"
	"github.com/floof-os/floofos-cli/internal/vpp"
	"golang.org/x/term"
)

func StartInteractiveShell() error {
	displayWelcome()

	config := &readline.Config{
		Prompt:            buildPrompt(),
		HistoryFile:       getHistoryFile(),
		AutoComplete:      nil,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
		UniqueEditLine:    true,
	}

	rl, err := readline.NewEx(config)
	if err != nil {
		return fmt.Errorf("failed to initialize shell: %w", err)
	}
	defer rl.Close()

	for {
		rl.SetPrompt(buildPrompt())

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					break
				} else {
					continue
				}
			} else if err == io.EOF {
				break
			}
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.HasSuffix(line, " ?") || line == "?" {
			showInlineHelp(line)
			continue
		}

		if handleBuiltinCommand(line) {
			continue
		}

		executeCommandInternal(line, true)
	}

	return nil
}

func displayWelcome() {
	fmt.Println("   ______          ___ ____  ____")
	fmt.Println("  / __/ /__  ___  / _/ __ \\/ __/")
	fmt.Println(" / _/ / _ \\/ _ \\/ _/ /_/ /\\ \\  ")
	fmt.Println("/_/ /_/\\___/\\___/_/  \\____/___/  ")
	fmt.Println()
}

var currentPrompt = "floof"

func buildPrompt() string {
	if IsConfigurationMode() {
		return currentPrompt + "(config)# "
	}
	return currentPrompt + "> "
}

func SetPrompt(hostname string) {
	if hostname != "" {
		currentPrompt = hostname
	}
}

func getHistoryFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.floofctl_history"
}

func showInlineHelp(line string) {
	baseCmd := strings.TrimSpace(strings.TrimSuffix(line, "?"))
	baseCmd = strings.TrimSpace(baseCmd)

	if baseCmd == "" {
		if IsOperationalMode() {
			fmt.Println("\nOperational Mode - Available commands:")
			fmt.Println("  show          Display information (VPP + BIRD)")
			fmt.Println("  configure     Enter configuration mode")
			fmt.Println("  start shell   Access system shell (requires root password)")
			fmt.Println("  help          Show this help")
			fmt.Println()
			fmt.Println("Use 'show ?' to see all VPP and BIRD show commands")
			return
		} else {
			fmt.Println("\nConfiguration Mode:")
			fmt.Println("  set           Configure settings")
			fmt.Println("  show          Display information")
			fmt.Println("  delete        Remove configuration")
			fmt.Println("  commit        Apply changes")
			fmt.Println("  backup        Backup management")
			fmt.Println("  exit/end      Return to operational mode")
			fmt.Println()
			return
		}
	}

	if showFloofOSInlineHelp(baseCmd) {
		return
	}

	vppClient := vpp.NewClient()
	vppOutput, vppErr := vppClient.ExecuteWithHelp(baseCmd)

	birdClient := bird.NewClient()
	birdOutput, birdErr := birdClient.ExecuteWithHelp(baseCmd)

	if vppErr == nil && vppOutput != "" {
		fmt.Print(vppOutput)
		if !strings.HasSuffix(vppOutput, "\n") {
			fmt.Println()
		}
	}

	if birdErr == nil && birdOutput != "" {
		fmt.Print(birdOutput)
		if !strings.HasSuffix(birdOutput, "\n") {
			fmt.Println()
		}
	}

	if (vppErr != nil || vppOutput == "") && (birdErr != nil || birdOutput == "") {
		fmt.Printf("No help available for: %s\n", baseCmd)
	}
}

func showFloofOSInlineHelp(cmd string) bool {
	words := strings.Fields(strings.ToLower(cmd))
	if len(words) == 0 {
		return false
	}

	switch words[0] {
	case "set":
		return showSetInlineHelp(words[1:])
	case "show":
		return showShowInlineHelp(words[1:])
	case "delete":
		return showDeleteInlineHelp(words[1:])
	case "start":
		if len(words) == 1 {
			fmt.Println("  shell         Access system shell")
			return true
		}
		if len(words) == 2 && words[1] == "shell" {
			fmt.Println("  <cr>")
			return true
		}
	}

	return false
}

func showSetInlineHelp(words []string) bool {
	if len(words) == 0 {
		fmt.Println("  service       Configure services (SSH, SNMP)")
		fmt.Println("  hostname      Set system hostname")
		fmt.Println("  bgp           Configure BGP (pathvector)")
		return true
	}

	if words[0] == "service" {
		if len(words) == 1 {
			fmt.Println("  ssh           SSH service configuration")
			fmt.Println("  snmp          SNMP service configuration")
			return true
		}

		if words[1] == "ssh" {
			if len(words) == 2 {
				fmt.Println("  port            SSH port (1-65535)")
				fmt.Println("  root-login      Root login permission")
				fmt.Println("  password-auth   Password authentication")
				fmt.Println("  listen-address  Listen address binding")
				return true
			}
			if len(words) == 3 {
				switch words[2] {
				case "port":
					fmt.Println("  <1-65535>     Port number")
					return true
				case "root-login", "password-auth":
					fmt.Println("  enable        Enable this setting")
					fmt.Println("  disable       Disable this setting")
					return true
				case "listen-address":
					fmt.Println("  <ip-address>  IP address to bind (e.g., 10.0.0.1, ::)")
					return true
				}
			}
			if len(words) == 4 {
				fmt.Println("  <cr>")
				return true
			}
		}

		if words[1] == "snmp" {
			if len(words) == 2 {
				fmt.Println("  enable        Enable SNMP service")
				fmt.Println("  disable       Disable SNMP service")
				fmt.Println("  community     Set community string")
				fmt.Println("  location      Set system location")
				fmt.Println("  contact       Set system contact")
				return true
			}
			if len(words) == 3 {
				switch words[2] {
				case "enable", "disable":
					fmt.Println("  <cr>")
					return true
				case "community", "location", "contact":
					fmt.Println("  <string>      Value to set")
					return true
				}
			}
			if len(words) >= 4 {
				fmt.Println("  <cr>")
				return true
			}
		}
	}

	return false
}

func showShowInlineHelp(words []string) bool {
	if len(words) == 0 {
		fmt.Println("  service         Show service configuration")
		fmt.Println("  configuration   Show all configuration")
		fmt.Println("  system          Show system information")
		fmt.Println("  bgp             Show BGP status")
		return true
	}

	if words[0] == "service" {
		if len(words) == 1 {
			fmt.Println("  ssh             Show SSH configuration")
			fmt.Println("  snmp            Show SNMP configuration")
			return true
		}
		if len(words) == 2 {
			fmt.Println("  <cr>")
			return true
		}
	}

	return false
}

func showDeleteInlineHelp(words []string) bool {
	if len(words) == 0 {
		fmt.Println("  service       Delete/reset service configuration")
		return true
	}

	if words[0] == "service" {
		if len(words) == 1 {
			fmt.Println("  ssh           Reset SSH settings to default")
			fmt.Println("  snmp          Disable and reset SNMP")
			return true
		}

		if words[1] == "ssh" {
			if len(words) == 2 {
				fmt.Println("  port            Reset to default (22)")
				fmt.Println("  root-login      Reset to default (disabled)")
				fmt.Println("  password-auth   Reset to default (enabled)")
				fmt.Println("  listen-address  Reset to default (0.0.0.0)")
				return true
			}
			if len(words) == 3 {
				fmt.Println("  <cr>")
				return true
			}
		}

		if words[1] == "snmp" {
			if len(words) == 2 {
				fmt.Println("  <cr>            Disable SNMP completely")
				fmt.Println("  community       Reset to default (public)")
				fmt.Println("  location        Reset to default")
				fmt.Println("  contact         Reset to default")
				return true
			}
			if len(words) == 3 {
				fmt.Println("  <cr>")
				return true
			}
		}
	}

	return false
}

func handleBuiltinCommand(line string) bool {
	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	command := strings.ToLower(args[0])

	switch command {
	case "configure":
		if IsOperationalMode() {
			SetMode(ConfigurationMode)
			fmt.Println("Entering configuration mode...")
			return true
		}
		return false

	case "start":
		if len(args) >= 2 && strings.ToLower(args[1]) == "shell" {
			handleStartShell()
			return true
		}
		return false

	case "exit", "quit", "end":
		if IsConfigurationMode() {
			SetMode(OperationalMode)
			fmt.Println("Exiting configuration mode...")
			return true
		}
		fmt.Println("Use 'start shell' to access system shell (requires root password)")
		return true

	case "help":
		showHelp()
		return true

	case "status":
		showStatus()
		return true

	case "clear", "cls":
		fmt.Print("\033[2J\033[H")
		return true

	case "history":
		showHistory()
		return true

	case "version":
		showVersion()
		return true

	default:
		return false
	}
}

func handleStartShell() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error: Failed to get current user")
		return
	}

	if currentUser.Uid == "0" {
		fmt.Println("Starting system shell...")
		startSystemShell()
		return
	}

	fmt.Println("Authorization required for system shell access.")
	fmt.Print("Password: ")

	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		fmt.Println("Error reading password")
		return
	}

	if authenticateRoot(string(password)) {
		fmt.Println("Starting system shell...")
		startSystemShellAsRoot(string(password))
	} else {
		fmt.Println("Authentication failed. Access denied.")
	}
}

func authenticateRoot(password string) bool {
	cmd := exec.Command("su", "-c", "true", "root")
	cmd.Stdin = strings.NewReader(password + "\n")
	err := cmd.Run()
	return err == nil
}

func startSystemShell() {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func startSystemShellAsRoot(password string) {
	cmd := exec.Command("su", "-", "root")
	cmd.Stdin = strings.NewReader(password + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Shell exited: %v\n", err)
	}
}

func showHelp() {
	fmt.Println("FloofCTL Help")
	fmt.Println("=============")
	fmt.Println()

	fmt.Println("Current Mode: " + GetCurrentMode().String())
	fmt.Println()

	fmt.Println("Mode Commands:")
	fmt.Println("  configure             - Enter configuration mode (full access)")
	fmt.Println("  start shell           - Access system shell (requires root password)")
	fmt.Println("  exit/end              - Return to operational mode (config mode only)")
	fmt.Println()

	fmt.Println("Built-in Commands:")
	fmt.Println("  help                  - Show this help message")
	fmt.Println("  status                - Show service status")
	fmt.Println("  version               - Show FloofCTL version")
	fmt.Println("  clear/cls             - Clear screen")
	fmt.Println("  history               - Show command history")
	fmt.Println()

	if IsOperationalMode() {
		fmt.Println("Operational Mode (Read-Only):")
		fmt.Println("  show <...>            - Display information (VPP/BIRD/FloofOS)")
		fmt.Println("  show configuration    - Show all configurations")
		fmt.Println("  show bgp              - Show pathvector status")
		fmt.Println("  configure             - Enter configuration mode")
		fmt.Println()
	} else {
		fmt.Println("Configuration Mode (Full Access):")
		fmt.Println()
		fmt.Println("VPP Commands (pass-through to vppctl):")
		fmt.Println("  show version          - Show VPP version")
		fmt.Println("  show interface        - Show VPP interfaces")
		fmt.Println("  set interface <...>   - Configure VPP interface")
		fmt.Println("  create <...>          - Create VPP resources")
		fmt.Println("  <any vppctl command>  - Direct pass-through to vppctl")
		fmt.Println()

		fmt.Println("BIRD Commands (pass-through to birdc):")
		fmt.Println("  show protocols        - Show BIRD protocols")
		fmt.Println("  show route            - Show BIRD routing table")
		fmt.Println("  configure soft        - Reload BIRD configuration")
		fmt.Println("  enable <protocol>     - Enable protocol")
		fmt.Println("  disable <protocol>    - Disable protocol")
		fmt.Println("  <any birdc command>   - Direct pass-through to birdc")
		fmt.Println()

		fmt.Println("FloofOS Commands:")
		fmt.Println("  commit                - Commit VPP configuration")
		fmt.Println("  commit bgp            - Generate and apply BGP config")
		fmt.Println("  set bgp               - Edit pathvector.yml")
		fmt.Println("  set hostname <name>   - Change prompt hostname")
		fmt.Println("  backup create [name]  - Create configuration backup")
		fmt.Println("  rollback [id]         - Rollback configuration")
		fmt.Println()
	}

	fmt.Println("Tips:")
	fmt.Println("  - Use TAB for dynamic completion from VPP/BIRD/FloofOS")
	fmt.Println("  - Append ? to any command for inline help")
	fmt.Println("  - Operational mode: show commands only")
	fmt.Println("  - Configuration mode: full VPP + BIRD access")
	fmt.Println("  - Type 'configure' to enter config mode")
	fmt.Println("  - Type 'exit' or 'end' to return to operational mode (config mode)")
	fmt.Println("  - Type 'start shell' for system shell access")
	fmt.Println()
}

func showStatus() {
	fmt.Println("FloofCTL Status")
	fmt.Println("===============")
	fmt.Println()

	status := GetServiceStatus()
	for service, available := range status {
		if available {
			fmt.Printf("✓ %s: Available and responding\n", service)
		} else {
			fmt.Printf("✗ %s: Not available or not responding\n", service)
		}
	}
	fmt.Println()

	hostname, _ := os.Hostname()
	fmt.Printf("Hostname: %s\n", hostname)

	wd, err := os.Getwd()
	if err == nil {
		fmt.Printf("Working Directory: %s\n", wd)
	}
}

func showHistory() {
	fmt.Println("Command History")
	fmt.Println("===============")
	fmt.Println()
	fmt.Println("History functionality requires readline history to be implemented")
}

func showVersion() {
	fmt.Println("FloofCTL Version Information")
	fmt.Println("============================")
	fmt.Println()

	fmt.Println("FloofCTL: v1.0.0-dev")
	fmt.Println("Built for: FloofOS")
	fmt.Println("Go Version: go1.21+")
	fmt.Println()

	vppClient := vpp.NewClient()
	if vppClient.IsAvailable() {
		if version, err := vppClient.GetVersion(); err == nil {
			fmt.Println("VPP Version:")
			fmt.Println(version)
		}
	}

	birdClient := bird.NewClient()
	if birdClient.IsAvailable() {
		if version, err := birdClient.GetVersion(); err == nil {
			fmt.Println("BIRD Status:")
			fmt.Println(version)
		}
	}
}
