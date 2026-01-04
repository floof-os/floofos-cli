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
	"path/filepath"
	"strings"
)

const (
	sshKeysDir       = "/home"
	sshdConfigFile   = "/etc/ssh/sshd_config"
	sshdConfigBackup = "/etc/ssh/sshd_config.floofos.backup"
)

func AddSSHKey(username, publicKey string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if !strings.HasPrefix(publicKey, "ssh-rsa") &&
		!strings.HasPrefix(publicKey, "ssh-ed25519") &&
		!strings.HasPrefix(publicKey, "ecdsa-sha2-") {
		return fmt.Errorf("invalid public key format")
	}

	userHome := filepath.Join("/home", username)
	if _, err := os.Stat(userHome); os.IsNotExist(err) {
		return fmt.Errorf("user %s does not exist", username)
	}

	sshDir := filepath.Join(userHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	cmd := exec.Command("chown", username+":"+username, sshDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set ownership: %w\nOutput: %s", err, output)
	}

	authKeysFile := filepath.Join(sshDir, "authorized_keys")

	existingKeys := ""
	if data, err := os.ReadFile(authKeysFile); err == nil {
		existingKeys = string(data)
	}

	if strings.Contains(existingKeys, publicKey) {
		return fmt.Errorf("public key already exists for user %s", username)
	}

	newContent := existingKeys
	if !strings.HasSuffix(newContent, "\n") && newContent != "" {
		newContent += "\n"
	}
	newContent += publicKey + "\n"

	if err := os.WriteFile(authKeysFile, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	cmd = exec.Command("chown", username+":"+username, authKeysFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set key ownership: %w\nOutput: %s", err, output)
	}

	return nil
}

func DeleteSSHKey(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	userHome := filepath.Join("/home", username)
	authKeysFile := filepath.Join(userHome, ".ssh", "authorized_keys")

	if _, err := os.Stat(authKeysFile); os.IsNotExist(err) {
		return fmt.Errorf("no SSH keys found for user %s", username)
	}

	if err := os.Remove(authKeysFile); err != nil {
		return fmt.Errorf("failed to delete SSH keys: %w", err)
	}

	return nil
}

func ListSSHKeys() (string, error) {
	var output strings.Builder

	entries, err := os.ReadDir(sshKeysDir)
	if err != nil {
		return "", fmt.Errorf("failed to read home directory: %w", err)
	}

	foundKeys := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		username := entry.Name()
		authKeysFile := filepath.Join(sshKeysDir, username, ".ssh", "authorized_keys")

		if _, err := os.Stat(authKeysFile); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(authKeysFile)
		if err != nil {
			continue
		}

		var validKeys []string
		for _, key := range strings.Split(string(data), "\n") {
			key = strings.TrimSpace(key)
			if key != "" && !strings.HasPrefix(key, "#") {
				validKeys = append(validKeys, key)
			}
		}

		if len(validKeys) > 0 {
			output.WriteString(fmt.Sprintf("user %s:\n", username))
			for i, key := range validKeys {
				keyPreview := key
				if len(keyPreview) > 70 {
					keyPreview = keyPreview[:70] + "..."
				}
				output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, keyPreview))
			}
			foundKeys = true
		}
	}

	if !foundKeys {
		output.WriteString("no ssh keys configured\n")
	}

	return output.String(), nil
}

func EnablePasswordAuth() error {
	return setPasswordAuth(true)
}

func DisablePasswordAuth() error {
	return setPasswordAuth(false)
}

func setPasswordAuth(enable bool) error {
	if _, err := os.Stat(sshdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", sshdConfigFile, sshdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup sshd_config: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	value := "no"
	if enable {
		value = "yes"
	}

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PasswordAuthentication") {
			lines[i] = fmt.Sprintf("PasswordAuthentication %s", value)
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, fmt.Sprintf("PasswordAuthentication %s", value))
	}

	newConfig := strings.Join(lines, "\n")
	if err := os.WriteFile(sshdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh-dataplane.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart SSH: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetSSHConfig() (string, error) {
	var output strings.Builder

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return "", fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	settings := map[string]string{
		"PasswordAuthentication": "yes",
		"PubkeyAuthentication":   "yes",
		"PermitRootLogin":        "no",
		"Port":                   "22",
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		for key := range settings {
			if strings.HasPrefix(trimmed, key) {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					settings[key] = parts[1]
				}
			}
		}
	}

	listenAddr, _ := GetListenAddress()

	output.WriteString("SSH Service Configuration:\n")
	output.WriteString(fmt.Sprintf("  Port:              %s\n", settings["Port"]))
	output.WriteString(fmt.Sprintf("  Listen Address:    %s\n", listenAddr))
	output.WriteString(fmt.Sprintf("  Root Login:        %s\n", formatEnabled(settings["PermitRootLogin"])))
	output.WriteString(fmt.Sprintf("  Password Auth:     %s\n", formatEnabled(settings["PasswordAuthentication"])))
	output.WriteString(fmt.Sprintf("  Pubkey Auth:       %s\n", formatEnabled(settings["PubkeyAuthentication"])))

	cmd := exec.Command("systemctl", "is-active", "ssh-dataplane.service")
	statusOutput, _ := cmd.CombinedOutput()
	status := strings.TrimSpace(string(statusOutput))
	output.WriteString(fmt.Sprintf("  Service:           %s\n", status))

	return output.String(), nil
}

func formatEnabled(value string) string {
	switch value {
	case "yes":
		return "enabled"
	case "no":
		return "disabled"
	default:
		return value
	}
}

func SetSSHPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	if _, err := os.Stat(sshdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", sshdConfigFile, sshdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup sshd_config: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Port ") || strings.HasPrefix(trimmed, "#Port ") {
			lines[i] = fmt.Sprintf("Port %d", port)
			found = true
			break
		}
	}

	if !found {
		for i, line := range lines {
			if strings.Contains(line, "AddressFamily") {
				lines = append(lines[:i], append([]string{fmt.Sprintf("Port %d", port)}, lines[i:]...)...)
				break
			}
		}
	}

	newConfig := strings.Join(lines, "\n")
	if err := os.WriteFile(sshdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}

	if err := updateFail2banSSHPort(port); err != nil {
		fmt.Printf("Warning: failed to update fail2ban SSH port: %v\n", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh-dataplane.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart SSH: %w\nOutput: %s", err, output)
	}

	return nil
}

func SetRootLogin(enable bool) error {
	if _, err := os.Stat(sshdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", sshdConfigFile, sshdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup sshd_config: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	value := "no"
	if enable {
		value = "yes"
	}

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PermitRootLogin") || strings.HasPrefix(trimmed, "#PermitRootLogin") {
			lines[i] = fmt.Sprintf("PermitRootLogin %s", value)
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, fmt.Sprintf("PermitRootLogin %s", value))
	}

	newConfig := strings.Join(lines, "\n")
	if err := os.WriteFile(sshdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh-dataplane.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart SSH: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetSSHPort() (int, error) {
	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return 22, fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Port ") {
			var port int
			fmt.Sscanf(trimmed, "Port %d", &port)
			if port > 0 {
				return port, nil
			}
		}
	}

	return 22, nil
}

func updateFail2banSSHPort(port int) error {
	fail2banConfig := "/etc/fail2ban/jail.d/floofos.local"

	data, err := os.ReadFile(fail2banConfig)
	if err != nil {
		return nil
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "port") {
			lines[i] = fmt.Sprintf("port = %d", port)
			found = true
			break
		}
	}

	if !found {
		for i, line := range lines {
			if strings.Contains(line, "[sshd]") {
				lines = append(lines[:i+1], append([]string{fmt.Sprintf("port = %d", port)}, lines[i+1:]...)...)
				break
			}
		}
	}

	newConfig := strings.Join(lines, "\n")
	if err := os.WriteFile(fail2banConfig, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write fail2ban config: %w", err)
	}

	exec.Command("fail2ban-client", "reload").Run()

	return nil
}

func SetListenAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	if _, err := os.Stat(sshdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", sshdConfigFile, sshdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup sshd_config: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ListenAddress") || strings.HasPrefix(trimmed, "#ListenAddress") {
			continue
		}
		if strings.HasPrefix(trimmed, "AddressFamily") || strings.HasPrefix(trimmed, "#AddressFamily") {
			continue
		}
		newLines = append(newLines, line)
	}

	var insertLines []string
	if strings.Contains(address, ":") {
		insertLines = []string{
			"AddressFamily inet6",
			fmt.Sprintf("ListenAddress %s", address),
		}
	} else {
		insertLines = []string{
			"AddressFamily inet",
			fmt.Sprintf("ListenAddress %s", address),
		}
	}

	for i, line := range newLines {
		if strings.HasPrefix(line, "Port ") {
			newLines = append(newLines[:i+1], append(insertLines, newLines[i+1:]...)...)
			break
		}
	}

	newConfig := strings.Join(newLines, "\n")
	if err := os.WriteFile(sshdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh-dataplane.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart SSH: %w\nOutput: %s", err, output)
	}

	return nil
}

func GetListenAddress() (string, error) {
	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return "0.0.0.0", fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	var addresses []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ListenAddress ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				addresses = append(addresses, parts[1])
			}
		}
	}

	if len(addresses) == 0 {
		return "0.0.0.0", nil
	}

	return strings.Join(addresses, ", "), nil
}

func ResetSSHListenAddress() error {
	if _, err := os.Stat(sshdConfigBackup); os.IsNotExist(err) {
		cmd := exec.Command("cp", sshdConfigFile, sshdConfigBackup)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to backup sshd_config: %w\nOutput: %s", err, output)
		}
	}

	data, err := os.ReadFile(sshdConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	config := string(data)
	lines := strings.Split(config, "\n")

	// Remove all ListenAddress lines
	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ListenAddress ") {
			newLines = append(newLines, line)
		}
	}

	// Add default ListenAddress entries after Port line
	insertLines := []string{
		"ListenAddress 0.0.0.0",
		"ListenAddress ::",
	}

	for i, line := range newLines {
		if strings.HasPrefix(line, "Port ") {
			newLines = append(newLines[:i+1], append(insertLines, newLines[i+1:]...)...)
			break
		}
	}

	newConfig := strings.Join(newLines, "\n")
	if err := os.WriteFile(sshdConfigFile, []byte(newConfig), 0644); err != nil {
		return fmt.Errorf("failed to write sshd_config: %w", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh-dataplane.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart SSH: %w\nOutput: %s", err, output)
	}

	return nil
}
