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
	"strings"
)

const (
	fail2banConfigDir  = "/etc/fail2ban"
	fail2banJailLocal  = "/etc/fail2ban/jail.local"
	fail2banFloofLocal = "/etc/fail2ban/jail.d/floofos.local"
)

func EnableFail2ban() error {
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return fmt.Errorf("fail2ban not installed: %w", err)
	}

	if err := createFloofOSJail(); err != nil {
		return fmt.Errorf("failed to create jail config: %w", err)
	}

	cmd := exec.Command("systemctl", "enable", "fail2ban.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable fail2ban: %w\nOutput: %s", err, output)
	}

	cmd = exec.Command("systemctl", "start", "fail2ban.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start fail2ban: %w\nOutput: %s", err, output)
	}

	return nil
}

func DisableFail2ban() error {
	cmd := exec.Command("systemctl", "stop", "fail2ban.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop fail2ban: %w\nOutput: %s", err, output)
	}

	cmd = exec.Command("systemctl", "disable", "fail2ban.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable fail2ban: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetFail2banStatus() (string, error) {
	var output strings.Builder

	cmd := exec.Command("systemctl", "is-active", "fail2ban.service")
	serviceOutput, err := cmd.CombinedOutput()

	status := strings.TrimSpace(string(serviceOutput))
	if err != nil {
		if status == "inactive" {
			output.WriteString("Fail2ban: disabled\n")
			output.WriteString("\nTo enable: set security fail2ban enable\n")
			return output.String(), nil
		}
		return "unknown", fmt.Errorf("failed to check status: %w", err)
	}

	output.WriteString("Fail2ban: enabled\n")

	maxRetry := 3
	banTime := 600
	findTime := 600

	configData, err := os.ReadFile(fail2banFloofLocal)
	if err == nil {
		lines := strings.Split(string(configData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "maxretry") {
				fmt.Sscanf(line, "maxretry = %d", &maxRetry)
			}
			if strings.HasPrefix(line, "bantime") {
				fmt.Sscanf(line, "bantime = %d", &banTime)
			}
			if strings.HasPrefix(line, "findtime") {
				fmt.Sscanf(line, "findtime = %d", &findTime)
			}
		}
	}

	output.WriteString(fmt.Sprintf("Max retry: %d attempts\n", maxRetry))
	output.WriteString(fmt.Sprintf("Ban time: %d seconds\n", banTime))
	output.WriteString(fmt.Sprintf("Find time: %d seconds\n", findTime))

	cmd = exec.Command("fail2ban-client", "status", "sshd")
	jailOutput, err := cmd.CombinedOutput()
	if err == nil {
		jailStr := string(jailOutput)
		currentlyBanned := 0
		totalBanned := 0

		lines := strings.Split(jailStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Currently banned:") {
				fmt.Sscanf(line, "   |- Currently banned: %d", &currentlyBanned)
			}
			if strings.Contains(line, "Total banned:") {
				fmt.Sscanf(line, "   `- Total banned: %d", &totalBanned)
			}
		}

		output.WriteString(fmt.Sprintf("Currently banned: %d IPs\n", currentlyBanned))
		output.WriteString(fmt.Sprintf("Total banned: %d IPs\n", totalBanned))
	}

	return output.String(), nil
}

func GetBannedIPs() (string, error) {
	cmd := exec.Command("fail2ban-client", "status", "sshd")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get banned IPs: %w\nOutput: %s", err, output)
	}

	return string(output), nil
}

func SetMaxRetry(maxRetry int) error {
	if maxRetry < 1 || maxRetry > 100 {
		return fmt.Errorf("maxretry must be between 1 and 100")
	}

	config := fmt.Sprintf(`[DEFAULT]
maxretry = %d
`, maxRetry)

	if err := os.WriteFile(fail2banFloofLocal, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return reloadFail2ban()
}

func SetBanTime(bantime int) error {
	if bantime < 60 {
		return fmt.Errorf("bantime must be at least 60 seconds")
	}

	existingConfig := ""
	if data, err := os.ReadFile(fail2banFloofLocal); err == nil {
		existingConfig = string(data)
	}

	config := existingConfig
	if strings.Contains(config, "bantime") {
		lines := strings.Split(config, "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "bantime") {
				lines[i] = fmt.Sprintf("bantime = %d", bantime)
			}
		}
		config = strings.Join(lines, "\n")
	} else {
		if !strings.Contains(config, "[DEFAULT]") {
			config = "[DEFAULT]\n" + config
		}
		lines := strings.Split(config, "\n")
		for i, line := range lines {
			if strings.Contains(line, "[DEFAULT]") {
				lines = append(lines[:i+1], append([]string{fmt.Sprintf("bantime = %d", bantime)}, lines[i+1:]...)...)
				break
			}
		}
		config = strings.Join(lines, "\n")
	}

	if err := os.WriteFile(fail2banFloofLocal, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return reloadFail2ban()
}

func UnbanIP(ip string) error {
	cmd := exec.Command("fail2ban-client", "set", "sshd", "unbanip", ip)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to unban IP: %w\nOutput: %s", err, output)
	}

	return nil
}

func reloadFail2ban() error {
	cmd := exec.Command("fail2ban-client", "reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload fail2ban: %w\nOutput: %s", err, output)
	}

	return nil
}

func createFloofOSJail() error {
	jailConfig := `# FloofOS Fail2ban Configuration
# Auto-generated by floofctl

[DEFAULT]
# Ban duration (seconds)
bantime = 600

# Find time window (seconds)
findtime = 600

# Maximum retry attempts
maxretry = 3

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600
`

	jailDir := "/etc/fail2ban/jail.d"
	if err := os.MkdirAll(jailDir, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	if err := os.WriteFile(fail2banFloofLocal, []byte(jailConfig), 0644); err != nil {
		return fmt.Errorf("failed to write jail config: %w", err)
	}

	return nil
}
