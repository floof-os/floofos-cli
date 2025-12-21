/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package bird

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Client struct {
	binaryPath string
	timeout    time.Duration
	socket     string
}

func NewClient() *Client {
	return &Client{
		binaryPath: "ip",
		timeout:    30 * time.Second,
		socket:     "",
	}
}

func NewClientWithSocket(socket string) *Client {
	return &Client{
		binaryPath: "birdc",
		timeout:    30 * time.Second,
		socket:     socket,
	}
}

func (c *Client) Execute(args []string) (string, error) {
	cmdArgs := []string{"netns", "exec", "dataplane", "birdc"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(c.binaryPath, cmdArgs...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return cleanBIRDOutput(string(output)), fmt.Errorf("birdc command failed: %w", err)
	}

	return cleanBIRDOutput(string(output)), nil
}

func (c *Client) ExecuteWithTimeout(args []string, timeout time.Duration) (string, error) {
	cmdArgs := []string{"netns", "exec", "dataplane", "birdc"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(c.binaryPath, cmdArgs...)

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
			return string(output), fmt.Errorf("birdc command failed: %w", err)
		}
		return string(output), nil
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("birdc command timed out after %v", timeout)
	}
}

func (c *Client) ExecuteInteractive(command string) (string, error) {
	cmdArgs := []string{"netns", "exec", "dataplane", "birdc"}

	cmd := exec.Command(c.binaryPath, cmdArgs...)

	cmd.Stdin = strings.NewReader(command + "\nquit\n")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("birdc interactive command failed: %w", err)
	}

	return string(output), nil
}

func (c *Client) GetHelp(command string) (string, error) {
	if command == "" {
		return c.Execute([]string{"help"})
	}

	args := []string{"help", command}
	return c.Execute(args)
}

func (c *Client) GetVersion() (string, error) {
	return c.Execute([]string{"show", "status"})
}

func (c *Client) IsAvailable() bool {
	_, err := c.ExecuteWithTimeout([]string{"show", "status"}, 5*time.Second)
	return err == nil
}

func (c *Client) GetProtocols() ([]string, error) {
	output, err := c.Execute([]string{"show", "protocols"})
	if err != nil {
		return nil, err
	}

	return parseProtocols(output), nil
}

func (c *Client) GetRoutes(table string) (string, error) {
	if table == "" {
		return c.Execute([]string{"show", "route"})
	}

	return c.Execute([]string{"show", "route", "table", table})
}

func (c *Client) GetTables() ([]string, error) {
	output, err := c.Execute([]string{"show", "route", "tables"})
	if err != nil {
		return nil, err
	}

	return parseTables(output), nil
}

func (c *Client) GetCommands() ([]string, error) {
	output, err := c.Execute([]string{"help"})
	if err != nil {
		return nil, err
	}

	return parseCommands(output), nil
}

func (c *Client) ConfigureProtocol(protocol string, action string) (string, error) {
	switch action {
	case "enable":
		return c.Execute([]string{"enable", protocol})
	case "disable":
		return c.Execute([]string{"disable", protocol})
	case "restart":
		return c.Execute([]string{"restart", protocol})
	default:
		return "", fmt.Errorf("unknown action: %s", action)
	}
}

func (c *Client) ExecuteWithHelp(partialCommand string) (string, error) {
	args := strings.Fields(partialCommand)
	if len(args) == 0 {
		args = []string{"?"}
	} else {
		args = append(args, "?")
	}

	output, err := c.Execute(args)

	output = cleanBIRDOutput(output)

	return output, err
}

func cleanBIRDOutput(output string) string {
	lines := strings.Split(output, "\n")
	var cleaned []string

	for _, line := range lines {
		if strings.HasPrefix(line, "BIRD") ||
			strings.Contains(line, "ready") ||
			strings.HasPrefix(line, "birdc>") ||
			strings.TrimSpace(line) == "" && len(cleaned) == 0 {
			continue
		}
		cleaned = append(cleaned, line)
	}

	return strings.Join(cleaned, "\n")
}

func (c *Client) GetCompletions(partialCommand string) ([]string, error) {
	args := strings.Fields(partialCommand)

	if len(args) == 0 {
		return getBIRDBaseCommands(), nil
	}

	if strings.HasSuffix(partialCommand, "?") {
		cmdWithoutQ := strings.TrimSpace(strings.TrimSuffix(partialCommand, "?"))
		return c.queryBIRDHelp(cmdWithoutQ)
	}

	return getBIRDContextualCompletions(args, c), nil
}

func (c *Client) queryBIRDHelp(command string) ([]string, error) {
	helpCmd := command + " ?"
	output, err := c.ExecuteInteractive(helpCmd)
	if err != nil {
		return getBIRDContextualCompletions(strings.Fields(command), c), nil
	}

	return parseBIRDHelp(output), nil
}

func parseBIRDHelp(output string) []string {
	var completions []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BIRD") ||
			strings.HasPrefix(line, "Access") || strings.Contains(line, "error") {
			continue
		}

		words := strings.Fields(line)
		if len(words) > 0 {
			completions = append(completions, words[0])
		}
	}

	return completions
}

func getBIRDBaseCommands() []string {
	return []string{
		"show", "configure", "enable", "disable", "restart", "reload",
		"down", "up", "debug", "dump", "eval", "filter", "help",
	}
}

func getBIRDContextualCompletions(args []string, c *Client) []string {
	if len(args) == 0 {
		return getBIRDBaseCommands()
	}

	firstWord := args[0]

	switch firstWord {
	case "show":
		if len(args) == 1 {
			return []string{
				"status", "protocols", "protocol", "interfaces", "interface",
				"route", "routes", "symbols", "memory", "bfd",
			}
		}

		if args[1] == "protocol" && len(args) == 2 {
			protocols, err := c.GetProtocols()
			if err == nil {
				return protocols
			}
		}

		if args[1] == "route" && len(args) == 2 {
			return []string{"all", "count", "export", "filter", "for", "in", "limit", "stats", "table", "where"}
		}
	case "configure":
		if len(args) == 1 {
			return []string{"soft", "timeout", "undo", "confirm", "check", "all"}
		}
	case "enable", "disable", "restart":
		if len(args) == 1 {
			protocols, err := c.GetProtocols()
			if err == nil {
				return protocols
			}
		}
	}

	return []string{}
}

func parseProtocols(output string) []string {
	var protocols []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "BIRD") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && !strings.Contains(fields[0], "-") {
			protocols = append(protocols, fields[0])
		}
	}

	return protocols
}

func parseTables(output string) []string {
	var tables []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Table") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if field != "Table" && field != "Routes" {
					tables = append(tables, field)
				}
			}
		}
	}

	return tables
}

func parseCommands(output string) []string {
	var commands []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, " ") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				command := fields[0]
				if !strings.Contains(command, ".") && !strings.HasPrefix(command, "(") {
					commands = append(commands, command)
				}
			}
		}
	}

	return commands
}
