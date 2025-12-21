/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package pathvector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

const (
	PathvectorConfigPath = "/etc/pathvector.yml"

	MaskedConfigPath = "/tmp/.pv-config-edit"
)

var (
	successColor = color.New(color.FgGreen, color.Bold)
	errorColor   = color.New(color.FgRed, color.Bold)
	infoColor    = color.New(color.FgCyan)
)

func SetBGP() error {
	if err := copyToTemp(); err != nil {
		return err
	}

	infoColor.Println("% Opening BGP configuration editor...")

	editor := os.Getenv("EDITOR")
	if editor == "" {
		if _, err := exec.LookPath("nano"); err == nil {
			editor = "nano"
		} else {
			editor = "vi"
		}
	}

	cmd := exec.Command(editor, MaskedConfigPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.Remove(MaskedConfigPath)
		return fmt.Errorf("editor error: %w", err)
	}

	if err := copyFromTemp(); err != nil {
		os.Remove(MaskedConfigPath)
		return err
	}

	os.Remove(MaskedConfigPath)

	successColor.Println("% BGP configuration updated")
	infoColor.Println("% Run 'commit bgp' to apply changes")

	return nil
}

func CommitBGP() error {
	infoColor.Println("% Generating BGP configuration...")

	cmd := exec.Command("pathvector", "generate")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errorColor.Println("% BGP configuration generation failed:")
		fmt.Println(stderr.String())
		return fmt.Errorf("pathvector generate failed: %w", err)
	}

	successColor.Println("% BGP configuration complete")

	output := stdout.String()
	if strings.Contains(output, "peers") || strings.Contains(output, "routes") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "peer") || strings.Contains(line, "route") || strings.Contains(line, "configured") {
				infoColor.Println("%", strings.TrimSpace(line))
			}
		}
	}

	return nil
}

func ShowBGPSummary() error {
	cmd := exec.Command("pathvector", "status")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pathvector status failed: %w", err)
	}

	return nil
}

func ShowBGPConfig() error {
	content, err := os.ReadFile(PathvectorConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			infoColor.Println("% No BGP configuration found")
			return nil
		}
		return fmt.Errorf("cannot read BGP config: %w", err)
	}

	fmt.Println()
	color.New(color.FgYellow, color.Bold).Println("BGP Configuration (pathvector.yml)")
	fmt.Println(strings.Repeat("=", 70))

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		color.New(color.FgHiBlack).Printf("%4d  ", i+1)

		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			color.New(color.FgGreen).Println(line)
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			color.New(color.FgYellow).Print(parts[0] + ":")
			if len(parts) > 1 {
				fmt.Println(parts[1])
			} else {
				fmt.Println()
			}
		} else {
			fmt.Println(line)
		}
	}

	fmt.Println()
	return nil
}

func copyToTemp() error {
	data, err := os.ReadFile(PathvectorConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read config: %w", err)
	}

	return os.WriteFile(MaskedConfigPath, data, 0600)
}

func copyFromTemp() error {
	data, err := os.ReadFile(MaskedConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read edited config: %w", err)
	}

	return os.WriteFile(PathvectorConfigPath, data, 0644)
}
