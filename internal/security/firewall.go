/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package security

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	nftablesConfigDir        = "/etc/nftables.d"
	nftablesConfigFile       = "/etc/nftables.conf"
	floofosRulesFile         = "/etc/nftables.d/floofos.nft"
	nftablesDataplaneService = "nftables-dataplane.service"
)

type FirewallRule struct {
	Name       string
	Protocol   string
	Port       string
	SrcAddress string
	Action     string
}

func EnableFirewall() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables not installed: %w", err)
	}

	if err := os.MkdirAll(nftablesConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create nftables config dir: %w", err)
	}

	cmd := exec.Command("nft", "list", "table", "inet", "floofos")
	if _, err := cmd.CombinedOutput(); err != nil {
		baseRules := `#!/usr/sbin/nft -f

table inet floofos {
	chain input {
		type filter hook input priority 0; policy drop;
		
		iif "lo" accept
		ct state established,related accept
		tcp dport 22 ct state new limit rate 5/minute accept comment "system-ssh"
		tcp dport 179 accept comment "system-bgp"
		tcp sport 179 accept comment "system-bgp-out"
		udp dport 3784-3785 accept comment "system-bfd"
		udp sport 3784-3785 accept comment "system-bfd-out"
		udp dport 161 accept comment "system-snmp"
		ct state invalid drop
		counter log prefix "floofos-drop: " drop
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
	}

	chain output {
		type filter hook output priority 0; policy accept;
	}
}
`
		if err := os.WriteFile(floofosRulesFile, []byte(baseRules), 0644); err != nil {
			return fmt.Errorf("failed to create base rules: %w", err)
		}
	} else {
		output, _ := cmd.CombinedOutput()
		rulesetStr := string(output)

		if !strings.Contains(rulesetStr, `comment "system-`) {
			fmt.Println("Note: Upgrading firewall rules with system tags...")

			exec.Command("nft", "delete", "table", "inet", "floofos").Run()

			baseRules := `#!/usr/sbin/nft -f

table inet floofos {
	chain input {
		type filter hook input priority 0; policy drop;
		
		iif "lo" accept
		ct state established,related accept
		tcp dport 22 ct state new limit rate 5/minute accept comment "system-ssh"
		tcp dport 179 accept comment "system-bgp"
		tcp sport 179 accept comment "system-bgp-out"
		udp dport 3784-3785 accept comment "system-bfd"
		udp sport 3784-3785 accept comment "system-bfd-out"
		udp dport 161 accept comment "system-snmp"
		ct state invalid drop
		counter log prefix "floofos-drop: " drop
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
	}

	chain output {
		type filter hook output priority 0; policy accept;
	}
}
`
			if err := os.WriteFile(floofosRulesFile, []byte(baseRules), 0644); err != nil {
				return fmt.Errorf("failed to create base rules: %w", err)
			}
		}
	}

	loadCmd := exec.Command("nft", "-f", floofosRulesFile)
	if output, err := loadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load firewall rules: %w\nOutput: %s", err, output)
	}

	exec.Command("systemctl", "unmask", nftablesDataplaneService).Run()

	enableCmd := exec.Command("systemctl", "enable", nftablesDataplaneService)
	if output, err := enableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable nftables: %w\nOutput: %s", err, output)
	}

	startCmd := exec.Command("systemctl", "start", nftablesDataplaneService)
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start nftables: %w\nOutput: %s", err, output)
	}

	fmt.Println("firewall enabled")
	return nil
}

func DisableFirewall() error {
	flushCmd := exec.Command("nft", "flush", "ruleset")
	flushCmd.Run()

	stopCmd := exec.Command("systemctl", "stop", nftablesDataplaneService)
	if output, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop nftables: %w\nOutput: %s", err, output)
	}

	disableCmd := exec.Command("systemctl", "disable", nftablesDataplaneService)
	if output, err := disableCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable nftables: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetFirewallStatus() (string, error) {
	var output strings.Builder

	cmd := exec.Command("systemctl", "is-active", nftablesDataplaneService)
	serviceOutput, err := cmd.CombinedOutput()

	status := strings.TrimSpace(string(serviceOutput))
	if err != nil {
		if status == "inactive" {
			return "Firewall: disabled\n\nTo enable: set security firewall enable", nil
		}
		return "unknown", fmt.Errorf("failed to check status: %w", err)
	}

	cmd = exec.Command("nft", "list", "table", "inet", "floofos")
	rulesetOutput, err := cmd.CombinedOutput()
	if err != nil {
		return "Firewall: enabled\nError: Unable to list rules", nil
	}

	rulesetStr := string(rulesetOutput)
	rules := parseFirewallRules(rulesetStr)

	acceptCount := 0
	dropCount := 0
	for _, rule := range rules {
		if rule.Action == "accept" {
			acceptCount++
		} else if rule.Action == "drop" {
			dropCount++
		}
	}

	statInfo, _ := os.Stat(floofosRulesFile)
	var lastModified string
	if statInfo != nil {
		lastModified = statInfo.ModTime().Format("2006-01-02 15:04:05")
	} else {
		lastModified = "unknown"
	}

	output.WriteString("Firewall: enabled\n")
	output.WriteString("Policy: input drop, forward accept, output accept\n")
	output.WriteString(fmt.Sprintf("Rules: %d active (%d accept, %d drop)\n", acceptCount+dropCount, acceptCount, dropCount))
	output.WriteString(fmt.Sprintf("Last modified: %s\n", lastModified))

	output.WriteString("Control plane: protected\n")

	return output.String(), nil
}

func ListFirewallRules() (string, error) {
	cmd := exec.Command("nft", "list", "table", "inet", "floofos")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such file or directory") ||
			strings.Contains(err.Error(), "exit status 1") {
			return "Firewall is currently disabled\n\nTo enable: set security firewall enable", nil
		}
		return "", fmt.Errorf("failed to list rules: %w\nOutput: %s", err, output)
	}

	rulesetStr := string(output)
	rules := parseFirewallRules(rulesetStr)

	if len(rules) == 0 {
		return "No custom rules configured (system rules active)", nil
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%-20s %-8s %-15s %-15s %s\n", "Name", "Protocol", "Source", "Dest Port", "Action"))

	for _, rule := range rules {
		src := rule.SrcAddress
		if src == "" {
			src = "any"
		}
		result.WriteString(fmt.Sprintf("%-20s %-8s %-15s %-15s %s\n",
			rule.Name, rule.Protocol, src, rule.Port, rule.Action))
	}

	return result.String(), nil
}

func parseFirewallRules(rulesetStr string) []FirewallRule {
	var rules []FirewallRule

	lines := strings.Split(rulesetStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.Contains(line, "accept") && !strings.Contains(line, "drop") {
			continue
		}

		if strings.Contains(line, "type filter hook") ||
			strings.Contains(line, "policy") ||
			strings.Contains(line, "iif") ||
			strings.Contains(line, "counter log prefix") ||
			strings.Contains(line, "ct state established") ||
			strings.Contains(line, "ct state invalid") {
			continue
		}

		rule := FirewallRule{
			Name:       "unnamed",
			Protocol:   "any",
			Port:       "any",
			SrcAddress: "",
			Action:     "accept",
		}

		commentRegex := regexp.MustCompile(`comment "([^"]+)"`)
		if matches := commentRegex.FindStringSubmatch(line); len(matches) > 1 {
			rule.Name = matches[1]
		} else {
			continue
		}

		if strings.Contains(line, "tcp dport") {
			rule.Protocol = "tcp"
			portRegex := regexp.MustCompile(`tcp dport (\d+)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
				rule.Port = matches[1]
			}
		} else if strings.Contains(line, "udp dport") {
			rule.Protocol = "udp"
			portRegex := regexp.MustCompile(`udp dport ([\d-]+)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
				rule.Port = matches[1]
			}
		} else if strings.Contains(line, "tcp sport") {
			rule.Protocol = "tcp"
			portRegex := regexp.MustCompile(`tcp sport (\d+)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
				rule.Port = matches[1] + " (src)"
			}
		} else if strings.Contains(line, "udp sport") {
			rule.Protocol = "udp"
			portRegex := regexp.MustCompile(`udp sport ([\d-]+)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
				rule.Port = matches[1] + " (src)"
			}
		} else if strings.Contains(line, "ip protocol icmp") {
			rule.Protocol = "icmp"
			rule.Port = "any"
		} else if strings.Contains(line, "ip6 nexthdr ipv6-icmp") {
			rule.Protocol = "icmpv6"
			rule.Port = "any"
		}

		srcRegex := regexp.MustCompile(`ip saddr ([0-9./]+)`)
		if matches := srcRegex.FindStringSubmatch(line); len(matches) > 1 {
			rule.SrcAddress = matches[1]
		}

		if strings.Contains(line, "drop") {
			rule.Action = "drop"
		}

		rules = append(rules, rule)
	}

	return rules
}

func AddFirewallRule(name, protocol, port, srcAddress, action string) error {
	if name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	validProtocols := map[string]bool{"tcp": true, "udp": true}
	if protocol != "" && !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", protocol)
	}

	validActions := map[string]bool{"accept": true, "drop": true}
	if !validActions[action] {
		return fmt.Errorf("invalid action: %s (must be accept or drop)", action)
	}

	isSystemRule := strings.HasPrefix(name, "system-")
	if err := DeleteFirewallRule(name); err == nil {
		if isSystemRule {
			fmt.Printf("Warning: Overriding system rule '%s' with custom configuration\n", name)
		} else {
			fmt.Printf("Note: Replacing existing rule '%s'\n", name)
		}
	}

	if srcAddress == "" {
		srcAddress = "0.0.0.0/0"
	}

	var rule string
	if protocol == "icmp" || protocol == "" {
		if srcAddress != "0.0.0.0/0" {
			if protocol == "icmp" {
				rule = fmt.Sprintf("ip saddr %s ip protocol icmp %s comment \"%s\"", srcAddress, action, name)
			} else {
				rule = fmt.Sprintf("ip saddr %s %s comment \"%s\"", srcAddress, action, name)
			}
		} else {
			if protocol == "icmp" {
				rule = fmt.Sprintf("ip protocol icmp %s comment \"%s\"", action, name)
			} else {
				rule = fmt.Sprintf("%s comment \"%s\"", action, name)
			}
		}
	} else {
		if srcAddress != "0.0.0.0/0" {
			rule = fmt.Sprintf("ip saddr %s %s dport %s %s comment \"%s\"", srcAddress, protocol, port, action, name)
		} else {
			rule = fmt.Sprintf("%s dport %s %s comment \"%s\"", protocol, port, action, name)
		}
	}

	cmd := exec.Command("nft", "insert", "rule", "inet", "floofos", "input", "index", "6", rule)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add rule: %w\nOutput: %s", err, output)
	}

	return saveRuleset()
}

func DeleteFirewallRule(name string) error {
	cmd := exec.Command("nft", "-a", "list", "table", "inet", "floofos")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var handleToDelete string

	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("comment \"%s\"", name)) {
			handleRegex := regexp.MustCompile(`# handle (\d+)`)
			if matches := handleRegex.FindStringSubmatch(line); len(matches) > 1 {
				handleToDelete = matches[1]
				break
			}
		}
	}

	if handleToDelete == "" {
		return fmt.Errorf("rule '%s' not found", name)
	}

	cmd = exec.Command("nft", "delete", "rule", "inet", "floofos", "input", "handle", handleToDelete)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete rule: %w\nOutput: %s", err, output)
	}

	return saveRuleset()
}

func saveRuleset() error {
	time.Sleep(100 * time.Millisecond)

	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list ruleset: %w", err)
	}

	header := "#!/usr/sbin/nft -f\n\n"
	content := header + string(output)

	if err := os.WriteFile(floofosRulesFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to save ruleset: %w", err)
	}

	return nil
}
