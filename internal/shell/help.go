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

	"github.com/fatih/color"
	"github.com/floof-os/floofos-cli/internal/bird"
	"github.com/floof-os/floofos-cli/internal/vpp"
	"github.com/floof-os/floofos-cli/pkg/detector"
)

func HandleHelpRequest(command string) error {
	cleanCommand := detector.GetCommandWithoutHelp(command)

	if strings.TrimSpace(cleanCommand) == "" {
		return showGeneralHelp()
	}

	cmdType := detector.DetectCommandType(cleanCommand)

	switch cmdType {
	case detector.VPP:
		return showVPPHelp(cleanCommand)
	case detector.BIRD:
		return showBIRDHelp(cleanCommand)
	case detector.FloofOS:
		return showFloofOSHelp(cleanCommand)
	default:
		return showCommandHelp(cleanCommand)
	}
}

func showGeneralHelp() error {
	color.Cyan("FloofCTL Help System")
	color.Cyan("====================")
	fmt.Println()

	color.White("Available Command Types:")
	fmt.Println()

	color.Green("Built-in Commands:")
	fmt.Println("  help                  - Show help information")
	fmt.Println("  status                - Show service status")
	fmt.Println("  version               - Show version information")
	fmt.Println("  clear/cls             - Clear screen")
	fmt.Println("  start shell           - Access system shell (requires root password)")
	fmt.Println("  exit/quit/end         - Return to operational mode (config mode only)")
	fmt.Println()

	color.Green("VPP Commands (vppctl pass-through):")
	fmt.Println("  show <object>         - Display VPP information")
	fmt.Println("  set <parameter>       - Configure VPP settings")
	fmt.Println("  clear <counter>       - Clear VPP counters")
	fmt.Println("  create <interface>    - Create VPP interfaces")
	fmt.Println("  <command>?            - Get help for specific VPP command")
	fmt.Println()

	color.Green("BIRD Commands (birdc pass-through):")
	fmt.Println("  show <object>         - Display BIRD information")
	fmt.Println("  configure <action>    - Configure BIRD")
	fmt.Println("  enable/disable <proto> - Control protocols")
	fmt.Println("  <command>?            - Get help for specific BIRD command")
	fmt.Println()

	color.Green("FloofOS Commands:")
	fmt.Println("  backup <action>       - Configuration backup management")
	fmt.Println("  generate <type>       - Generate configurations")
	fmt.Println("  rollback <target>     - Rollback configurations")
	fmt.Println("  show configuration    - Display current configuration")
	fmt.Println("  show service ssh      - Display SSH configuration")
	fmt.Println("  show service snmp     - Display SNMP configuration")
	fmt.Println("  set service ssh ...   - Configure SSH service")
	fmt.Println("  set service snmp ...  - Configure SNMP service")
	fmt.Println()

	color.Yellow("Tips:")
	fmt.Println("  - Use TAB for command completion")
	fmt.Println("  - Append ? to any command for specific help")
	fmt.Println("  - Commands are automatically routed to appropriate services")
	fmt.Println("  - Type 'help <command>' for detailed command help")

	return nil
}

func showVPPHelp(command string) error {
	color.Green("VPP Command Help")
	color.Green("================")
	fmt.Println()

	if command == "" {
		color.White("VPP (Vector Packet Processing) Commands:")
		fmt.Println()
		showVPPCommandCategories()
		return nil
	}

	client := vpp.NewClient()
	if client.IsAvailable() {
		color.White("Getting help from VPP for: %s", command)
		fmt.Println()

		output, err := client.GetHelp(command)
		if err != nil {
			color.Red("Error getting VPP help: %v", err)
			return showVPPCommandHelp(command)
		}

		fmt.Println(output)
		return nil
	} else {
		color.Yellow("VPP is not available. Showing static help.")
		return showVPPCommandHelp(command)
	}
}

func showBIRDHelp(command string) error {
	color.Green("BIRD Command Help")
	color.Green("=================")
	fmt.Println()

	if command == "" {
		color.White("BIRD (BIRD Internet Routing Daemon) Commands:")
		fmt.Println()
		showBIRDCommandCategories()
		return nil
	}

	client := bird.NewClient()
	if client.IsAvailable() {
		color.White("Getting help from BIRD for: %s", command)
		fmt.Println()

		output, err := client.GetHelp(command)
		if err != nil {
			color.Red("Error getting BIRD help: %v", err)
			return showBIRDCommandHelp(command)
		}

		fmt.Println(output)
		return nil
	} else {
		color.Yellow("BIRD is not available. Showing static help.")
		return showBIRDCommandHelp(command)
	}
}

func showFloofOSHelp(command string) error {
	color.Green("FloofOS Command Help")
	color.Green("====================")
	fmt.Println()

	args := strings.Fields(command)
	if len(args) == 0 {
		showFloofOSCommandCategories()
		return nil
	}

	switch args[0] {
	case "backup":
		return showBackupHelp()
	case "generate":
		return showGenerateHelp()
	case "rollback":
		return showRollbackHelp()
	case "show":
		if len(args) > 1 && args[1] == "configuration" {
			return showConfigurationHelp()
		}
		return showFloofOSShowHelp()
	case "config":
		return showConfigHelp()
	case "service":
		return showServiceHelp()
	case "system":
		return showSystemHelp()
	case "network":
		return showNetworkHelp()
	default:
		color.Red("Unknown FloofOS command: %s", args[0])
		showFloofOSCommandCategories()
		return nil
	}
}

func showCommandHelp(command string) error {
	color.Yellow("Command Help")
	color.Yellow("============")
	fmt.Println()

	color.White("Unknown command: %s", command)
	fmt.Println()
	color.White("This command was not recognized as a VPP, BIRD, or FloofOS command.")
	color.White("It will be attempted as both VPP and BIRD commands when executed.")
	fmt.Println()

	color.White("Suggestions:")
	fmt.Println("  - Check spelling and try TAB completion")
	fmt.Println("  - Use 'help' to see all available commands")
	fmt.Println("  - Try 'show ?' or 'configure ?' for VPP/BIRD commands")

	return nil
}

func showVPPCommandCategories() {
	color.White("Show Commands:")
	fmt.Println("  show version          - VPP version information")
	fmt.Println("  show interface        - Interface status")
	fmt.Println("  show ip fib           - IP routing table")
	fmt.Println("  show runtime          - Runtime statistics")
	fmt.Println("  show hardware         - Hardware information")
	fmt.Println("  show memory           - Memory usage")
	fmt.Println()

	color.White("Set Commands:")
	fmt.Println("  set interface state   - Interface up/down")
	fmt.Println("  set ip neighbor       - Add ARP entry")
	fmt.Println("  set logging level     - Change log level")
	fmt.Println()

	color.White("Create/Delete Commands:")
	fmt.Println("  create loopback       - Create loopback interface")
	fmt.Println("  create bridge-domain  - Create bridge domain")
	fmt.Println("  delete <interface>    - Delete interface")
}

func showBIRDCommandCategories() {
	color.White("Show Commands:")
	fmt.Println("  show status           - BIRD daemon status")
	fmt.Println("  show protocols        - Protocol status")
	fmt.Println("  show route            - Routing table")
	fmt.Println("  show interfaces       - Interface status")
	fmt.Println()

	color.White("Configure Commands:")
	fmt.Println("  configure             - Reload configuration")
	fmt.Println("  configure soft        - Soft reload")
	fmt.Println("  configure check       - Check configuration")
	fmt.Println()

	color.White("Protocol Control:")
	fmt.Println("  enable <protocol>     - Enable protocol")
	fmt.Println("  disable <protocol>    - Disable protocol")
	fmt.Println("  restart <protocol>    - Restart protocol")
}

func showFloofOSCommandCategories() {
	color.White("Configuration Management:")
	fmt.Println("  backup create [name]  - Create configuration backup")
	fmt.Println("  backup list           - List available backups")
	fmt.Println("  rollback to <id>      - Rollback to backup")
	fmt.Println("  show configuration    - Show current config")
	fmt.Println()

	color.White("Generation:")
	fmt.Println("  generate config       - Generate base configuration")
	fmt.Println("  generate template     - Generate config template")
	fmt.Println("  generate keys         - Generate security keys")
	fmt.Println()

	color.White("System Management:")
	fmt.Println("  service start <name>  - Start system service")
	fmt.Println("  system status         - Show system status")
	fmt.Println("  network diagnose      - Network diagnostics")
}

func showBackupHelp() error {
	color.White("Backup Command Help")
	fmt.Println("===================")
	fmt.Println()
	fmt.Println("Usage: backup <action> [options]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  create [name]         - Create new backup with optional name")
	fmt.Println("  list                  - List all available backups")
	fmt.Println("  delete <id|name>      - Delete specific backup")
	fmt.Println("  info <id|name>        - Show backup information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  backup create pre-upgrade")
	fmt.Println("  backup list")
	fmt.Println("  backup info 2023-11-05-001")
	return nil
}

func showGenerateHelp() error {
	color.White("Generate Command Help")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Println("Usage: generate <type> [options]")
	fmt.Println()
	fmt.Println("Types:")
	fmt.Println("  config                - Generate base configuration")
	fmt.Println("  template              - Generate configuration template")
	fmt.Println("  script                - Generate automation script")
	fmt.Println("  keys                  - Generate security keys")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  generate config")
	fmt.Println("  generate template bgp")
	fmt.Println("  generate keys rsa")
	return nil
}

func showRollbackHelp() error {
	color.White("Rollback Command Help")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Println("Usage: rollback <action> [target]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  to <id|name>          - Rollback to specific backup")
	fmt.Println("  list                  - List rollback targets")
	fmt.Println("  info <id|name>        - Show rollback information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  rollback to pre-upgrade")
	fmt.Println("  rollback list")
	fmt.Println("  rollback info 2023-11-05-001")
	return nil
}

func showConfigurationHelp() error {
	color.White("Show Configuration Help")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Println("Usage: show configuration [section] [options]")
	fmt.Println()
	fmt.Println("Sections:")
	fmt.Println("  current               - Current active configuration")
	fmt.Println("  backup <id>           - Specific backup configuration")
	fmt.Println("  diff <id1> <id2>      - Difference between configurations")
	fmt.Println("  all                   - All configuration sections")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  show configuration current")
	fmt.Println("  show configuration backup pre-upgrade")
	fmt.Println("  show configuration diff current pre-upgrade")
	return nil
}

func showFloofOSShowHelp() error {
	color.White("FloofOS Show Commands")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Println("Available show commands:")
	fmt.Println("  show configuration    - Configuration management")
	fmt.Println("  show status           - System status")
	fmt.Println("  show logs             - System logs")
	fmt.Println("  show history          - Command history")
	return nil
}

func showConfigHelp() error {
	color.White("Config Command Help")
	fmt.Println("===================")
	fmt.Println()
	fmt.Println("Usage: config <action> [options]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  edit                  - Edit configuration")
	fmt.Println("  save                  - Save current configuration")
	fmt.Println("  load <file>           - Load configuration from file")
	fmt.Println("  validate              - Validate configuration")
	fmt.Println("  diff                  - Show configuration differences")
	return nil
}

func showServiceHelp() error {
	color.White("Service Command Help")
	fmt.Println("====================")
	fmt.Println()
	fmt.Println("SSH Service:")
	fmt.Println("  set service ssh port <1-65535>           - Change SSH port")
	fmt.Println("  set service ssh root-login <enable|disable>")
	fmt.Println("  set service ssh password-auth <enable|disable>")
	fmt.Println("  set service ssh listen-address <ip>      - Bind SSH to specific IP")
	fmt.Println("  show service ssh                         - Show SSH configuration")
	fmt.Println()
	fmt.Println("SNMP Service:")
	fmt.Println("  set service snmp enable                  - Enable SNMP")
	fmt.Println("  set service snmp disable                 - Disable SNMP")
	fmt.Println("  set service snmp community <string>      - Set community string")
	fmt.Println("  set service snmp location <string>       - Set location")
	fmt.Println("  set service snmp contact <string>        - Set contact")
	fmt.Println("  show service snmp                        - Show SNMP status")
	return nil
}

func showSystemHelp() error {
	color.White("System Command Help")
	fmt.Println("===================")
	fmt.Println()
	fmt.Println("Usage: system <action>")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  info                  - System information")
	fmt.Println("  status                - System status")
	fmt.Println("  update                - Update system")
	fmt.Println("  reboot                - Reboot system")
	fmt.Println("  shutdown              - Shutdown system")
	return nil
}

func showNetworkHelp() error {
	color.White("Network Command Help")
	fmt.Println("====================")
	fmt.Println()
	fmt.Println("Usage: network <action>")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  status                - Network status")
	fmt.Println("  configure             - Network configuration")
	fmt.Println("  test                  - Network connectivity test")
	fmt.Println("  diagnose              - Network diagnostics")
	return nil
}

func showVPPCommandHelp(command string) error {
	args := strings.Fields(command)
	if len(args) == 0 {
		return nil
	}

	switch args[0] {
	case "show":
		color.White("VPP Show Command Help")
		fmt.Println("Usage: show <object> [options]")
		fmt.Println("Common objects: version, interface, ip, hardware, runtime, memory")
	case "set":
		color.White("VPP Set Command Help")
		fmt.Println("Usage: set <parameter> <value>")
		fmt.Println("Common parameters: interface, ip, logging")
	default:
		color.White("VPP Command: %s", command)
		fmt.Println("No specific help available. Try executing with ? for VPP help.")
	}

	return nil
}

func showBIRDCommandHelp(command string) error {
	args := strings.Fields(command)
	if len(args) == 0 {
		return nil
	}

	switch args[0] {
	case "show":
		color.White("BIRD Show Command Help")
		fmt.Println("Usage: show <object> [options]")
		fmt.Println("Common objects: status, protocols, route, interfaces")
	case "configure":
		color.White("BIRD Configure Command Help")
		fmt.Println("Usage: configure [action]")
		fmt.Println("Actions: soft, check, undo, confirm")
	default:
		color.White("BIRD Command: %s", command)
		fmt.Println("No specific help available. Try executing with ? for BIRD help.")
	}

	return nil
}
