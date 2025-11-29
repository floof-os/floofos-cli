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
	"strings"

	"github.com/chzyer/readline"
	"github.com/floof-os/floofos-cli/internal/bird"
	"github.com/floof-os/floofos-cli/internal/vpp"
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
			fmt.Println("  help          Show this help")
			fmt.Println("  exit          Exit FloofCTL")
			fmt.Println()
			fmt.Println("Use 'show ?' to see all VPP and BIRD show commands")
			return
		} else {
			fmt.Println("\nConfiguration Mode:")
			fmt.Println("  FloofCTL commands: commit, backup, rollback, set hostname")
			fmt.Println("  exit/end      Return to operational mode")
			fmt.Println()
			fmt.Println("All VPP and BIRD commands available - use '<command> ?' for help")
			return
		}
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
		fmt.Println("Try checking 'vppctl' and 'birdc' documentation")
	}
}

func handleBuiltinCommand(line string) bool {
	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	command := args[0]

	switch command {
	case "configure":
		if IsOperationalMode() {
			SetMode(ConfigurationMode)
			fmt.Println("Entering configuration mode...")
			return true
		}
		return false

	case "exit", "quit":
		if IsConfigurationMode() {
			SetMode(OperationalMode)
			fmt.Println("Exiting configuration mode...")
			return true
		}
		fmt.Println("Goodbye!")
		os.Exit(0)
		return true

	case "end":
		if IsConfigurationMode() {
			SetMode(OperationalMode)
			fmt.Println("Returning to operational mode...")
			return true
		}
		return false

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

func showHelp() {
	fmt.Println("FloofCTL Help")
	fmt.Println("=============")
	fmt.Println()

	fmt.Println("Current Mode: " + GetCurrentMode().String())
	fmt.Println()

	fmt.Println("Mode Commands:")
	fmt.Println("  configure             - Enter configuration mode (full access)")
	fmt.Println("  exit                  - Exit current mode or FloofCTL")
	fmt.Println("  end                   - Return to operational mode")
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
	fmt.Println("  - Type 'exit' or 'end' to return to operational mode")
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
