/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package floofos

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/floof-os/floofos-cli/internal/security"
	"github.com/floof-os/floofos-cli/internal/snmp"
)

func ExecuteServiceCommand(args []string, isInteractive bool) error {
	if len(args) == 0 {
		return showServiceHelp()
	}

	action := strings.ToLower(args[0])

	switch action {
	case "ssh":
		return handleSSHCommand(args[1:])
	case "snmp":
		return handleSNMPCommand(args[1:])
	default:
		return fmt.Errorf("unknown service: %s\nAvailable services: ssh, snmp", action)
	}
}

func DeleteServiceCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: delete service <ssh|snmp> <setting>")
	}

	service := strings.ToLower(args[0])

	switch service {
	case "ssh":
		return deleteSSHSetting(args[1:])
	case "snmp":
		return deleteSNMPSetting(args[1:])
	default:
		return fmt.Errorf("unknown service: %s", service)
	}
}

func deleteSSHSetting(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: delete service ssh <port|root-login|password-auth|listen-address>")
	}

	setting := strings.ToLower(args[0])

	switch setting {
	case "port":
		if err := security.SetSSHPort(22); err != nil {
			return err
		}
		fmt.Println("SSH port reset to default (22)")
		return nil

	case "root-login":
		if err := security.SetRootLogin(false); err != nil {
			return err
		}
		fmt.Println("SSH root login reset to default (disabled)")
		return nil

	case "password-auth":
		if err := security.EnablePasswordAuth(); err != nil {
			return err
		}
		fmt.Println("SSH password auth reset to default (enabled)")
		return nil

	case "listen-address":
		if err := security.SetListenAddress("0.0.0.0"); err != nil {
			return err
		}
		fmt.Println("SSH listen address reset to default (0.0.0.0)")
		return nil

	default:
		return fmt.Errorf("unknown SSH setting: %s", setting)
	}
}

func deleteSNMPSetting(args []string) error {
	if len(args) == 0 {
		if err := snmp.DisableSNMP(); err != nil {
			return err
		}
		fmt.Println("SNMP service disabled and configuration reset")
		return nil
	}

	setting := strings.ToLower(args[0])

	switch setting {
	case "community":
		if err := snmp.SetCommunity("public"); err != nil {
			return err
		}
		fmt.Println("SNMP community reset to default (public)")
		return nil

	case "location":
		if err := snmp.SetLocation("FloofOS Router"); err != nil {
			return err
		}
		fmt.Println("SNMP location reset to default")
		return nil

	case "contact":
		if err := snmp.SetContact("admin@localhost"); err != nil {
			return err
		}
		fmt.Println("SNMP contact reset to default")
		return nil

	default:
		return fmt.Errorf("unknown SNMP setting: %s", setting)
	}
}

func handleSSHCommand(args []string) error {
	if len(args) == 0 {
		config, err := security.GetSSHConfig()
		if err != nil {
			return err
		}
		fmt.Print(config)
		return nil
	}

	subCmd := strings.ToLower(args[0])

	switch subCmd {
	case "port":
		if len(args) < 2 {
			port, err := security.GetSSHPort()
			if err != nil {
				return err
			}
			fmt.Printf("SSH port: %d\n", port)
			return nil
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid port number: %s", args[1])
		}
		if err := security.SetSSHPort(port); err != nil {
			return err
		}
		fmt.Printf("SSH port changed to %d\n", port)
		return nil

	case "root-login":
		if len(args) < 2 {
			config, err := security.GetSSHConfig()
			if err != nil {
				return err
			}
			fmt.Print(config)
			return nil
		}
		enable := strings.ToLower(args[1]) == "enable"
		if err := security.SetRootLogin(enable); err != nil {
			return err
		}
		if enable {
			fmt.Println("SSH root login enabled")
		} else {
			fmt.Println("SSH root login disabled")
		}
		return nil

	case "password-auth":
		if len(args) < 2 {
			config, err := security.GetSSHConfig()
			if err != nil {
				return err
			}
			fmt.Print(config)
			return nil
		}
		if strings.ToLower(args[1]) == "enable" {
			if err := security.EnablePasswordAuth(); err != nil {
				return err
			}
			fmt.Println("SSH password authentication enabled")
		} else {
			if err := security.DisablePasswordAuth(); err != nil {
				return err
			}
			fmt.Println("SSH password authentication disabled")
		}
		return nil

	case "listen-address":
		if len(args) < 2 {
			addr, err := security.GetListenAddress()
			if err != nil {
				return err
			}
			fmt.Printf("SSH listen address: %s\n", addr)
			return nil
		}
		if err := security.SetListenAddress(args[1]); err != nil {
			return err
		}
		fmt.Printf("SSH listen address set to: %s\n", args[1])
		fmt.Println("SSH service will only accept connections on this address")
		return nil

	default:
		return fmt.Errorf("unknown SSH command: %s\nUsage: set service ssh <port|root-login|password-auth|listen-address> <value>", subCmd)
	}
}

func handleSNMPCommand(args []string) error {
	if len(args) == 0 {
		status, err := snmp.GetSNMPStatus()
		if err != nil {
			return err
		}
		fmt.Print(status)
		return nil
	}

	subCmd := strings.ToLower(args[0])

	switch subCmd {
	case "enable":
		if err := snmp.EnableSNMP(); err != nil {
			return err
		}
		fmt.Println("SNMP service enabled")
		return nil

	case "disable":
		if err := snmp.DisableSNMP(); err != nil {
			return err
		}
		fmt.Println("SNMP service disabled")
		return nil

	case "community":
		if len(args) < 2 {
			config, err := snmp.GetSNMPConfig()
			if err != nil {
				return err
			}
			fmt.Print(config)
			return nil
		}
		if err := snmp.SetCommunity(args[1]); err != nil {
			return err
		}
		fmt.Printf("SNMP community set to: %s\n", args[1])
		return nil

	case "location":
		if len(args) < 2 {
			return fmt.Errorf("usage: set service snmp location <location>")
		}
		location := strings.Join(args[1:], " ")
		if err := snmp.SetLocation(location); err != nil {
			return err
		}
		fmt.Printf("SNMP location set to: %s\n", location)
		return nil

	case "contact":
		if len(args) < 2 {
			return fmt.Errorf("usage: set service snmp contact <contact>")
		}
		contact := strings.Join(args[1:], " ")
		if err := snmp.SetContact(contact); err != nil {
			return err
		}
		fmt.Printf("SNMP contact set to: %s\n", contact)
		return nil

	case "status":
		status, err := snmp.GetSNMPStatus()
		if err != nil {
			return err
		}
		fmt.Print(status)
		return nil

	case "config":
		config, err := snmp.GetSNMPConfig()
		if err != nil {
			return err
		}
		fmt.Print(config)
		return nil

	default:
		return fmt.Errorf("unknown SNMP command: %s\nUsage: set service snmp <enable|disable|community|location|contact>", subCmd)
	}
}

func showServiceHelp() error {
	fmt.Println("Service Configuration")
	fmt.Println("=====================")
	fmt.Println()
	fmt.Println("Available services:")
	fmt.Println()
	fmt.Println("  SSH:")
	fmt.Println("    set service ssh port <1-65535>")
	fmt.Println("    set service ssh root-login <enable|disable>")
	fmt.Println("    set service ssh password-auth <enable|disable>")
	fmt.Println("    set service ssh listen-address <ip-address>")
	fmt.Println("    show service ssh")
	fmt.Println()
	fmt.Println("  SNMP:")
	fmt.Println("    set service snmp enable")
	fmt.Println("    set service snmp disable")
	fmt.Println("    set service snmp community <string>")
	fmt.Println("    set service snmp location <string>")
	fmt.Println("    set service snmp contact <string>")
	fmt.Println("    show service snmp")
	fmt.Println()
	return nil
}

func ShowServiceSSH() error {
	config, err := security.GetSSHConfig()
	if err != nil {
		return err
	}
	fmt.Print(config)
	return nil
}

func ShowServiceSNMP() error {
	status, err := snmp.GetSNMPStatus()
	if err != nil {
		return err
	}
	fmt.Print(status)

	config, err := snmp.GetSNMPConfig()
	if err != nil {
		return err
	}
	fmt.Print(config)
	return nil
}
