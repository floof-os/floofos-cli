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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type ParsedOutput struct {
	Command string                 `json:"command"`
	Success bool                   `json:"success"`
	Data    map[string]interface{} `json:"data"`
	Raw     string                 `json:"raw"`
}

func ParseOutput(command string, output string) *ParsedOutput {
	parsed := &ParsedOutput{
		Command: command,
		Success: !strings.Contains(output, "error") && !strings.Contains(output, "failed"),
		Data:    make(map[string]interface{}),
		Raw:     output,
	}

	args := strings.Fields(command)
	if len(args) == 0 {
		return parsed
	}

	switch args[0] {
	case "show":
		if len(args) > 1 {
			parseShowCommand(args[1], args[2:], output, parsed)
		}
	case "set":
		parseSetCommand(args[1:], output, parsed)
	default:
		parsed.Data["output"] = output
	}

	return parsed
}

func parseShowCommand(subcommand string, args []string, output string, parsed *ParsedOutput) {
	switch subcommand {
	case "version":
		parseVersionOutput(output, parsed)
	case "interface", "interfaces":
		parseInterfaceOutput(output, parsed)
	case "ip":
		if len(args) > 0 {
			parseIPOutput(args[0], output, parsed)
		}
	case "hardware":
		parseHardwareOutput(output, parsed)
	case "runtime":
		parseRuntimeOutput(output, parsed)
	case "memory":
		parseMemoryOutput(output, parsed)
	case "buffers":
		parseBuffersOutput(output, parsed)
	default:
		parsed.Data["output"] = output
	}
}

func parseSetCommand(args []string, output string, parsed *ParsedOutput) {
	parsed.Data["output"] = output
	parsed.Success = !strings.Contains(strings.ToLower(output), "error")
}

func parseVersionOutput(output string, parsed *ParsedOutput) {
	version := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "vpp v") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				version["version"] = parts[1]
			}
			version["build_info"] = line
		}
	}

	parsed.Data["version"] = version
}

func parseInterfaceOutput(output string, parsed *ParsedOutput) {
	interfaces := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Name") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			iface := map[string]interface{}{
				"name":  fields[0],
				"idx":   fields[1],
				"admin": fields[2],
				"link":  fields[3],
				"mtu":   fields[4],
				"mac":   fields[5],
			}
			interfaces = append(interfaces, iface)
		}
	}

	parsed.Data["interfaces"] = interfaces
}

func parseIPOutput(subcommand string, output string, parsed *ParsedOutput) {
	switch subcommand {
	case "fib":
		parseIPFibOutput(output, parsed)
	case "neighbors":
		parseIPNeighborsOutput(output, parsed)
	default:
		parsed.Data["output"] = output
	}
}

func parseIPFibOutput(output string, parsed *ParsedOutput) {
	routes := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "Table") {
			continue
		}

		if strings.Contains(line, "via") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				route := map[string]interface{}{
					"prefix": parts[0],
					"raw":    line,
				}
				routes = append(routes, route)
			}
		}
	}

	parsed.Data["routes"] = routes
}

func parseIPNeighborsOutput(output string, parsed *ParsedOutput) {
	neighbors := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			neighbor := map[string]interface{}{
				"ip":        fields[0],
				"interface": fields[1],
				"mac":       fields[2],
				"flags":     strings.Join(fields[3:], " "),
			}
			neighbors = append(neighbors, neighbor)
		}
	}

	parsed.Data["neighbors"] = neighbors
}

func parseHardwareOutput(output string, parsed *ParsedOutput) {
	hardware := make(map[string]interface{})
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		hardware["raw"] = output
	}

	parsed.Data["hardware"] = hardware
}

func parseRuntimeOutput(output string, parsed *ParsedOutput) {
	runtime := make(map[string]interface{})

	uptimeRegex := regexp.MustCompile(`Time now (\d+\.\d+), (.+) since last reset`)
	if matches := uptimeRegex.FindStringSubmatch(output); len(matches) >= 3 {
		runtime["current_time"] = matches[1]
		runtime["uptime"] = matches[2]
	}

	runtime["raw"] = output
	parsed.Data["runtime"] = runtime
}

func parseMemoryOutput(output string, parsed *ParsedOutput) {
	memory := make(map[string]interface{})
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.Contains(line, "bytes") {
			memory["raw"] = output
			break
		}
	}

	parsed.Data["memory"] = memory
}

func parseBuffersOutput(output string, parsed *ParsedOutput) {
	buffers := make(map[string]interface{})
	buffers["raw"] = output
	parsed.Data["buffers"] = buffers
}

func (p *ParsedOutput) ToJSON() (string, error) {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal parsed output: %w", err)
	}
	return string(data), nil
}

func (p *ParsedOutput) ToFormattedString() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Command: %s\n", p.Command))
	sb.WriteString(fmt.Sprintf("Success: %t\n", p.Success))

	if len(p.Data) > 0 {
		sb.WriteString("Parsed Data:\n")
		for key, value := range p.Data {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}

	return sb.String()
}
