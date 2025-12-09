/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package snmp

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	snmpdConfigFile        = "/etc/snmp/snmpd-dataplane.conf"
	snmpdConfigBackup      = "/etc/snmp/snmpd-dataplane.conf.backup"
	vppSnmpAgentService    = "vpp-snmp-agent.service"
	snmpdService           = "snmpd-dataplane.service"
	vppSnmpAgentConfigFile = "/etc/vpp/dataplane.yaml"
	agentxSocketPath       = "/var/run/agentx/master"
)

type SNMPConfig struct {
	Community       string
	Location        string
	Contact         string
	PollingInterval int
}

func EnableSNMP() error {
	snmpdPath := ""
	for _, path := range []string{"/usr/sbin/snmpd", "/usr/local/sbin/snmpd", "snmpd"} {
		if p, err := exec.LookPath(path); err == nil {
			snmpdPath = p
			break
		}
	}
	if snmpdPath == "" {
		return fmt.Errorf("snmpd not installed. Install: apt-get install snmpd")
	}

	vppSnmpPath := ""
	for _, path := range []string{"/usr/local/bin/vpp-snmp-agent", "/usr/bin/vpp-snmp-agent", "vpp-snmp-agent"} {
		if p, err := exec.LookPath(path); err == nil {
			vppSnmpPath = p
			break
		}
	}
	if vppSnmpPath == "" {
		return fmt.Errorf("vpp-snmp-agent not installed. Check build script")
	}

	os.MkdirAll("/var/run/agentx", 0755)

	if err := createSNMPDConfig(); err != nil {
		return fmt.Errorf("failed to create snmpd config: %w", err)
	}

	exec.Command("systemctl", "unmask", snmpdService).Run()
	exec.Command("systemctl", "daemon-reload").Run()

	cmd := exec.Command("systemctl", "enable", snmpdService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable snmpd-dataplane: %w\nOutput: %s", err, output)
	}

	cmd = exec.Command("systemctl", "start", snmpdService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start snmpd-dataplane: %w\nOutput: %s", err, output)
	}

	exec.Command("systemctl", "unmask", vppSnmpAgentService).Run()

	cmd = exec.Command("systemctl", "enable", vppSnmpAgentService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable vpp-snmp-agent: %w\nOutput: %s", err, output)
	}

	cmd = exec.Command("systemctl", "start", vppSnmpAgentService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start vpp-snmp-agent: %w\nOutput: %s", err, output)
	}

	return nil
}

func DisableSNMP() error {
	cmd := exec.Command("systemctl", "stop", vppSnmpAgentService)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: failed to stop vpp-snmp-agent: %s\n", output)
	}

	cmd = exec.Command("systemctl", "disable", vppSnmpAgentService)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: failed to disable vpp-snmp-agent: %s\n", output)
	}

	cmd = exec.Command("systemctl", "stop", snmpdService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop snmpd: %w\nOutput: %s", err, output)
	}

	cmd = exec.Command("systemctl", "disable", snmpdService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable snmpd: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetSNMPStatus() (string, error) {
	var output strings.Builder

	output.WriteString("SNMP Agent Status\n")
	output.WriteString(strings.Repeat("-", 50) + "\n")

	snmpdPath := ""
	for _, path := range []string{"/usr/sbin/snmpd", "/usr/local/sbin/snmpd"} {
		if _, err := os.Stat(path); err == nil {
			snmpdPath = path
			break
		}
	}
	if snmpdPath == "" {
		output.WriteString("\nsnmpd: NOT INSTALLED\n")
		output.WriteString("Install: apt-get install snmpd\n")
		return output.String(), nil
	}

	cmd := exec.Command("systemctl", "is-active", snmpdService)
	snmpdStatus, _ := cmd.CombinedOutput()
	status := strings.TrimSpace(string(snmpdStatus))
	output.WriteString(fmt.Sprintf("\nsnmpd service: %s\n", status))

	vppSnmpPath := ""
	for _, path := range []string{"/usr/local/bin/vpp-snmp-agent", "/usr/bin/vpp-snmp-agent"} {
		if _, err := os.Stat(path); err == nil {
			vppSnmpPath = path
			break
		}
	}

	if vppSnmpPath != "" {
		cmd = exec.Command("systemctl", "is-active", vppSnmpAgentService)
		vppSnmpStatus, _ := cmd.CombinedOutput()
		agentStatus := strings.TrimSpace(string(vppSnmpStatus))
		output.WriteString(fmt.Sprintf("vpp-snmp-agent: %s\n", agentStatus))
	} else {
		output.WriteString("vpp-snmp-agent: not installed\n")
	}

	if status == "active" {
		cmd = exec.Command("ss", "-lunp")
		ssOutput, err := cmd.CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(string(ssOutput), "\n") {
				if strings.Contains(line, "snmpd") && strings.Contains(line, "161") {
					output.WriteString("\nListening: UDP 161 (SNMP)\n")
					break
				}
			}
		}
	}

	return output.String(), nil
}

func GetSNMPConfig() (string, error) {
	var output strings.Builder

	output.WriteString("SNMP Configuration:\n")
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	data, err := os.ReadFile(snmpdConfigFile)
	if err != nil {
		return "", fmt.Errorf("failed to read snmpd config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "rocommunity") ||
			strings.HasPrefix(trimmed, "syslocation") ||
			strings.HasPrefix(trimmed, "syscontact") ||
			strings.HasPrefix(trimmed, "sysname") {
			output.WriteString(fmt.Sprintf("  %s\n", trimmed))
		}
	}

	serviceFile := "/etc/systemd/system/vpp-snmp-agent.service"
	if serviceData, err := os.ReadFile(serviceFile); err == nil {
		for _, line := range strings.Split(string(serviceData), "\n") {
			if strings.HasPrefix(line, "ExecStart=") {
				output.WriteString("\nvpp-snmp-agent command:\n")
				output.WriteString(fmt.Sprintf("  %s\n", strings.TrimPrefix(line, "ExecStart=")))
				break
			}
		}
	}

	return output.String(), nil
}

func SetCommunity(community string) error {
	if community == "" {
		return fmt.Errorf("community string cannot be empty")
	}

	return updateSNMPDConfigLine("rocommunity", fmt.Sprintf("rocommunity %s default -V systemonly", community))
}

func SetLocation(location string) error {
	if location == "" {
		return fmt.Errorf("location cannot be empty")
	}

	return updateSNMPDConfigLine("syslocation", fmt.Sprintf("syslocation %s", location))
}

func SetContact(contact string) error {
	if contact == "" {
		return fmt.Errorf("contact cannot be empty")
	}

	return updateSNMPDConfigLine("syscontact", fmt.Sprintf("syscontact %s", contact))
}

func SetPollingInterval(interval int) error {
	if interval < 5 || interval > 300 {
		return fmt.Errorf("polling interval must be between 5 and 300 seconds")
	}

	serviceFile := "/etc/systemd/system/vpp-snmp-agent.service"
	data, err := os.ReadFile(serviceFile)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "ExecStart=") {
			lines[i] = fmt.Sprintf("ExecStart=/usr/sbin/ip netns exec dataplane /usr/local/bin/vpp-snmp-agent -agentx.addr /var/run/agentx/master -vppcfg /etc/vpp/dataplane.yaml -vppstats.period %d", interval)
			break
		}
	}

	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(serviceFile, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()

	cmd := exec.Command("systemctl", "restart", vppSnmpAgentService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart vpp-snmp-agent: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetStatistics() (string, error) {
	cmd := exec.Command("snmpget", "-v2c", "-c", "public", "localhost", "SNMPv2-MIB::sysUpTime.0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to query SNMP: %w\nOutput: %s", err, output)
	}

	return string(output), nil
}

func updateSNMPDConfigLine(prefix, newLine string) error {
	if _, err := os.Stat(snmpdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", snmpdConfigFile, snmpdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup snmpd.conf: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(snmpdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read snmpd.conf: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = newLine
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, newLine)
	}

	newConfig := strings.Join(lines, "\n")
	if err := os.WriteFile(snmpdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write snmpd.conf: %w", err)
	}

	cmd := exec.Command("systemctl", "reload", snmpdService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload snmpd: %w\nOutput: %s", err, output)
	}

	return nil
}

func createSNMPDConfig() error {
	if _, err := os.Stat(snmpdConfigFile); err == nil {
		if _, err := os.Stat(snmpdConfigBackup); os.IsNotExist(err) {
			exec.Command("cp", snmpdConfigFile, snmpdConfigBackup).Run()
		}
	}

	config := `# FloofOS SNMP Configuration for Dataplane Namespace
# Auto-generated by floofctl for govpp-snmp-agentx integration

# System information
sysLocation    FloofOS Router
sysContact     admin@localhost
sysServices    72

# Listen on all interfaces in dataplane namespace
agentAddress udp:161,udp6:[::1]:161

# Community strings (read-only)
rocommunity public default
rocommunity6 public default

# AgentX master configuration (required for govpp-snmp-agentx)
master agentx
agentXSocket /var/run/agentx/master

# System defaults
sysObjectID 1.3.6.1.4.1.8072.3.2.10

# Disk monitoring
disk /

# Load average monitoring
load 10 10 10
`

	if err := os.MkdirAll("/etc/snmp", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/snmp directory: %w", err)
	}

	if err := os.MkdirAll("/var/run/agentx", 0755); err != nil {
		return fmt.Errorf("failed to create /var/run/agentx directory: %w", err)
	}

	if err := os.WriteFile(snmpdConfigFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write snmpd config: %w", err)
	}

	return nil
}
