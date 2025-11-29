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
	"strings"

	"github.com/floof-os/floofos-cli/internal/bird"
	"github.com/floof-os/floofos-cli/internal/floofos"
	"github.com/floof-os/floofos-cli/internal/vpp"
	"github.com/floof-os/floofos-cli/pkg/detector"
)

func ExecuteCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command provided")
	}

	command := strings.Join(args, " ")
	return executeCommandInternal(command, false)
}

func executeCommandInternal(command string, isInteractive bool) error {
	isHelp := detector.IsHelpRequest(command)
	if isHelp {
		command = detector.GetCommandWithoutHelp(command)
	}

	if IsOperationalMode() {
		if !isShowCommand(command) && !isFloofOSCommand(command) {
			return fmt.Errorf("command not available in operational mode. Use 'configure' to enter configuration mode")
		}
	}

	if isInteractive && detector.IsAmbiguousCommand(command) {
		fmt.Println("Ambiguous command (exists in both VPP and BIRD):")
		fmt.Println("  For VPP:  " + command)
		fmt.Println("  For BIRD: " + command)
		fmt.Println()
		fmt.Println("Defaulting to VPP. Use 'show protocols' to access BIRD.")
		fmt.Println()
	}

	cmdType := detector.DetectCommandType(command)

	switch cmdType {
	case detector.VPP:
		return executeVPPCommand(command, isHelp, isInteractive)
	case detector.BIRD:
		return executeBIRDCommand(command, isHelp, isInteractive)
	case detector.FloofOS:
		return executeFloofOSCommand(command, isInteractive)
	case detector.Unknown:
		if isInteractive {
			return fmt.Errorf("unknown command: %s", command)
		} else {
			err := executeVPPCommand(command, isHelp, false)
			if err != nil {
				return executeBIRDCommand(command, isHelp, false)
			}
			return nil
		}
	}

	return nil
}

func isShowCommand(command string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(command)), "show")
}

func isFloofOSCommand(command string) bool {
	cmdType := detector.DetectCommandType(command)
	return cmdType == detector.FloofOS
}

func executeVPPCommand(command string, isHelp bool, isInteractive bool) error {
	client := vpp.NewClient()

	if !client.IsAvailable() {
		if isInteractive {
			fmt.Println("Warning: VPP is not available or not responding")
			return fmt.Errorf("VPP service is not available")
		} else {
			return fmt.Errorf("VPP service is not available")
		}
	}

	args := strings.Fields(command)

	var output string
	var err error

	if isHelp {
		output, err = client.GetHelp(command)
	} else {
		output, err = client.Execute(args)
	}

	if output != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}

	return err
}

func executeBIRDCommand(command string, isHelp bool, isInteractive bool) error {
	client := bird.NewClient()

	if !client.IsAvailable() {
		if isInteractive {
			fmt.Println("Warning: BIRD is not available or not responding")
			return fmt.Errorf("BIRD service is not available")
		} else {
			return fmt.Errorf("BIRD service is not available")
		}
	}

	args := strings.Fields(command)

	var output string
	var err error

	if isHelp {
		output, err = client.GetHelp(command)
	} else {
		output, err = client.Execute(args)
	}

	if output != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}

	return err
}

func executeFloofOSCommand(command string, isInteractive bool) error {
	args := strings.Fields(command)
	if len(args) == 0 {
		return fmt.Errorf("empty FloofOS command")
	}

	commandStr := strings.ToLower(strings.Join(args, " "))

	switch {
	case commandStr == "commit":
		return floofos.VPPcfgCommit()
	case strings.HasPrefix(commandStr, "commit bgp"):
		return floofos.CommitBGP()

	case strings.HasPrefix(commandStr, "set hostname"):
		parts := strings.Fields(commandStr)
		if len(parts) < 3 {
			return fmt.Errorf("usage: set hostname <name>")
		}
		hostname := parts[2]
		fmt.Printf("Hostname set to: %s\n", hostname)
		return nil
	case strings.HasPrefix(commandStr, "set bgp"):
		return floofos.SetBGP()

	case commandStr == "show configuration" || commandStr == "show running-config":
		return floofos.ShowConfiguration("default")
	case strings.HasPrefix(commandStr, "show configuration"):
		format := "default"
		if strings.Contains(commandStr, "yaml") {
			format = "yaml"
		}
		return floofos.ShowConfiguration(format)
	case commandStr == "show bgp" || commandStr == "show bgp summary":
		return floofos.ShowBGPSummary()
	case strings.HasPrefix(commandStr, "show bgp config"):
		return floofos.ShowBGPConfig()

	case strings.HasPrefix(commandStr, "backup"):
		return floofos.ExecuteBackup(args[1:], isInteractive)

	case strings.HasPrefix(commandStr, "rollback"):
		return floofos.ExecuteRollback(args[1:], isInteractive)

	case strings.HasPrefix(commandStr, "generate"):
		return floofos.ExecuteGenerate(args[1:], isInteractive)

	case args[0] == "config":
		return floofos.ExecuteConfig(args[1:], isInteractive)
	case args[0] == "service":
		return floofos.ExecuteService(args[1:], isInteractive)
	case args[0] == "system":
		return floofos.ExecuteSystem(args[1:], isInteractive)
	case args[0] == "network":
		return floofos.ExecuteNetwork(args[1:], isInteractive)

	default:
		return fmt.Errorf("unknown FloofOS command: %s", args[0])
	}
}

func displayVPPOutput(command string, output string) {
	fmt.Print(output)
}

func displayBIRDOutput(command string, output string) {
	fmt.Print(output)
}

func GetDryRunInfo(command string) string {
	cmdType := detector.DetectCommandType(command)

	switch cmdType {
	case detector.VPP:
		return fmt.Sprintf("Would execute VPP command: %s", command)
	case detector.BIRD:
		return fmt.Sprintf("Would execute BIRD command: %s", command)
	case detector.FloofOS:
		return fmt.Sprintf("Would execute FloofOS command: %s", command)
	default:
		return fmt.Sprintf("Would attempt to execute command: %s (type unknown)", command)
	}
}

func ValidateCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("empty command")
	}

	dangerous := []string{"shutdown", "halt", "reboot", "rm -rf", "format"}
	lowerCommand := strings.ToLower(command)

	for _, danger := range dangerous {
		if strings.Contains(lowerCommand, danger) {
			return fmt.Errorf("potentially dangerous command detected: %s", danger)
		}
	}

	return nil
}

func IsServiceAvailable(serviceType detector.CommandType) bool {
	switch serviceType {
	case detector.VPP:
		client := vpp.NewClient()
		return client.IsAvailable()
	case detector.BIRD:
		client := bird.NewClient()
		return client.IsAvailable()
	default:
		return false
	}
}

func GetServiceStatus() map[string]bool {
	return map[string]bool{
		"VPP":  IsServiceAvailable(detector.VPP),
		"BIRD": IsServiceAvailable(detector.BIRD),
	}
}
