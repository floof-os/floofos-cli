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

	output.WriteString("SSH Public Keys:\n")
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

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

		keys := strings.Split(string(data), "\n")
		keyCount := 0
		for _, key := range keys {
			key = strings.TrimSpace(key)
			if key != "" && !strings.HasPrefix(key, "#") {
				keyCount++
			}
		}

		if keyCount > 0 {
			output.WriteString(fmt.Sprintf("User: %s (%d key(s))\n", username, keyCount))
			for i, key := range keys {
				key = strings.TrimSpace(key)
				if key != "" && !strings.HasPrefix(key, "#") {
					keyPreview := key
					if len(keyPreview) > 70 {
						keyPreview = keyPreview[:70] + "..."
					}
					output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, keyPreview))
				}
			}
			output.WriteString("\n")
			foundKeys = true
		}
	}

	if !foundKeys {
		output.WriteString("No SSH keys configured\n")
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

	cmd := exec.Command("systemctl", "reload", "sshd.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("systemctl", "reload", "ssh.service")
		if output2, err2 := cmd.CombinedOutput(); err2 != nil {
			return fmt.Errorf("failed to reload SSH: %w\nOutput: %s / %s", err, output, output2)
		}
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

	output.WriteString("SSH Daemon Configuration:\n")
	output.WriteString(strings.Repeat("=", 80) + "\n\n")

	settings := map[string]string{
		"PasswordAuthentication": "unknown",
		"PubkeyAuthentication":   "unknown",
		"PermitRootLogin":        "unknown",
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

	for key, value := range settings {
		output.WriteString(fmt.Sprintf("  %-30s: %s\n", key, value))
	}

	cmd := exec.Command("systemctl", "is-active", "sshd.service")
	statusOutput, err := cmd.CombinedOutput()
	if err != nil {
		cmd = exec.Command("systemctl", "is-active", "ssh.service")
		statusOutput, _ = cmd.CombinedOutput()
	}

	status := strings.TrimSpace(string(statusOutput))
	output.WriteString(fmt.Sprintf("\n  Service Status: %s\n", status))

	return output.String(), nil
}
