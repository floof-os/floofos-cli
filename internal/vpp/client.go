/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package vpp

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Client struct {
	binaryPath string
	timeout    time.Duration
}

func NewClient() *Client {
	return &Client{
		binaryPath: "vppctl",
		timeout:    30 * time.Second,
	}
}

func (c *Client) Execute(args []string) (string, error) {
	cmd := exec.Command(c.binaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("vppctl command failed: %w", err)
	}

	return string(output), nil
}

func (c *Client) ExecuteWithTimeout(args []string, timeout time.Duration) (string, error) {
	cmd := exec.Command(c.binaryPath, args...)

	done := make(chan struct{})
	var output []byte
	var err error

	go func() {
		output, err = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
		if err != nil {
			return string(output), fmt.Errorf("vppctl command failed: %w", err)
		}
		return string(output), nil
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("vppctl command timed out after %v", timeout)
	}
}

func (c *Client) GetHelp(command string) (string, error) {
	args := strings.Fields(command)
	if len(args) > 0 {
		args = append(args, "?")
		return c.Execute(args)
	}

	return c.Execute([]string{"help"})
}

func (c *Client) GetVersion() (string, error) {
	return c.Execute([]string{"show", "version"})
}

func (c *Client) IsAvailable() bool {
	_, err := c.ExecuteWithTimeout([]string{"show", "version"}, 5*time.Second)
	return err == nil
}

func (c *Client) GetInterfaces() ([]string, error) {
	output, err := c.Execute([]string{"show", "interface"})
	if err != nil {
		return nil, err
	}

	return parseInterfaces(output), nil
}

func (c *Client) GetCommands() ([]string, error) {
	output, err := c.Execute([]string{"help"})
	if err != nil {
		return nil, err
	}

	return parseCommands(output), nil
}

func (c *Client) ExecuteWithHelp(partialCommand string) (string, error) {
	args := strings.Fields(partialCommand)
	if len(args) == 0 {
		return "", fmt.Errorf("empty command")
	}

	helpArgs := append(args, "?")
	output, err := c.Execute(helpArgs)

	return output, err
}

func (c *Client) GetCompletions(partialCommand string) ([]string, error) {
	args := strings.Fields(partialCommand)

	if len(args) == 0 {
		return getVPPBaseCommands(), nil
	}

	helpArgs := append(args, "?")
	output, err := c.Execute(helpArgs)
	if err != nil {
		return getContextualCompletions(args), nil
	}

	return parseVPPHelp(output), nil
}

func getVPPBaseCommands() []string {
	return []string{
		"show", "set", "clear", "create", "delete", "enable", "disable",
		"test", "trace", "packet-generator", "api", "cli", "exec",
	}
}

func getContextualCompletions(args []string) []string {
	if len(args) == 0 {
		return getVPPBaseCommands()
	}

	firstWord := args[0]

	switch firstWord {
	case "show":
		if len(args) == 1 {
			return []string{
				"version", "hardware", "interface", "int", "ip", "ip6",
				"runtime", "errors", "buffers", "memory", "threads",
				"node", "trace", "api", "fib", "adj", "arp",
			}
		}
	case "set":
		if len(args) == 1 {
			return []string{
				"interface", "int", "ip", "logging", "verbose",
			}
		}
	case "clear":
		if len(args) == 1 {
			return []string{
				"interface", "errors", "runtime", "trace", "hardware",
			}
		}
	}

	return []string{}
}

func parseVPPHelp(output string) []string {
	var suggestions []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "vpp#") || strings.HasPrefix(line, "DBGvpp#") {
			continue
		}

		words := strings.Fields(line)
		for _, word := range words {
			if word == "vpp#" || word == "DBGvpp#" || strings.HasPrefix(word, "[") {
				continue
			}
			if word != "" && !strings.Contains(word, "...") {
				suggestions = append(suggestions, word)
			}
		}
	}

	return suggestions
}

func parseInterfaces(output string) []string {
	var interfaces []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "Name") {
			interfaces = append(interfaces, fields[0])
		}
	}

	return interfaces
}

func parseCommands(output string) []string {
	var commands []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 {
			command := fields[0]
			if !strings.Contains(command, ":") && !strings.HasPrefix(command, "-") {
				commands = append(commands, command)
			}
		}
	}

	return commands
}
