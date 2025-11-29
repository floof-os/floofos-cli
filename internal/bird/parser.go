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
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ParsedOutput struct {
	Command   string                 `json:"command"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Raw       string                 `json:"raw"`
	Timestamp time.Time              `json:"timestamp"`
}

func ParseOutput(command string, output string) *ParsedOutput {
	parsed := &ParsedOutput{
		Command:   command,
		Success:   !strings.Contains(output, "error") && !strings.Contains(output, "Error"),
		Data:      make(map[string]interface{}),
		Raw:       output,
		Timestamp: time.Now(),
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
	case "configure":
		parseConfigureCommand(args[1:], output, parsed)
	case "enable", "disable", "restart":
		parseProtocolCommand(args, output, parsed)
	default:
		parsed.Data["output"] = output
	}
	
	return parsed
}

func parseShowCommand(subcommand string, args []string, output string, parsed *ParsedOutput) {
	switch subcommand {
	case "status":
		parseStatusOutput(output, parsed)
	case "protocols":
		parseProtocolsOutput(output, parsed)
	case "protocol":
		if len(args) > 0 {
			parseProtocolDetailOutput(args[0], output, parsed)
		}
	case "interfaces":
		parseInterfacesOutput(output, parsed)
	case "interface":
		if len(args) > 0 {
			parseInterfaceDetailOutput(args[0], output, parsed)
		}
	case "route", "routes":
		parseRoutesOutput(args, output, parsed)
	case "memory":
		parseMemoryOutput(output, parsed)
	case "symbols":
		parseSymbolsOutput(output, parsed)
	case "ospf":
		parseOSPFOutput(args, output, parsed)
	case "bgp":
		parseBGPOutput(args, output, parsed)
	case "bfd":
		parseBFDOutput(args, output, parsed)
	default:
		parsed.Data["output"] = output
	}
}

func parseConfigureCommand(args []string, output string, parsed *ParsedOutput) {
	parsed.Data["output"] = output
	parsed.Success = strings.Contains(output, "Reading configuration") || 
		strings.Contains(output, "Reconfigured")
}

func parseProtocolCommand(args []string, output string, parsed *ParsedOutput) {
	if len(args) >= 2 {
		parsed.Data["protocol"] = args[1]
		parsed.Data["action"] = args[0]
	}
	parsed.Data["output"] = output
	parsed.Success = !strings.Contains(strings.ToLower(output), "error")
}

func parseStatusOutput(output string, parsed *ParsedOutput) {
	status := make(map[string]interface{})
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		if strings.HasPrefix(line, "BIRD ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				status["version"] = parts[1]
			}
			status["status_line"] = line
		}
		
		if strings.Contains(line, "Router ID") {
			re := regexp.MustCompile(`Router ID is (\d+\.\d+\.\d+\.\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 2 {
				status["router_id"] = matches[1]
			}
		}
		
		if strings.Contains(line, "since") {
			status["uptime_info"] = line
		}
	}
	
	parsed.Data["status"] = status
}

func parseProtocolsOutput(output string, parsed *ParsedOutput) {
	protocols := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "BIRD") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			protocol := map[string]interface{}{
				"name":  fields[0],
				"proto": fields[1],
				"table": fields[2],
				"state": fields[3],
			}
			
			if len(fields) >= 5 {
				protocol["since"] = fields[4]
			}
			
			if len(fields) > 5 {
				protocol["info"] = strings.Join(fields[5:], " ")
			}
			
			protocols = append(protocols, protocol)
		}
	}
	
	parsed.Data["protocols"] = protocols
}

func parseProtocolDetailOutput(protocolName string, output string, parsed *ParsedOutput) {
	protocol := map[string]interface{}{
		"name": protocolName,
	}
	
	scanner := bufio.NewScanner(strings.NewReader(output))
	section := ""
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		if strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			protocol[section] = make(map[string]interface{})
			continue
		}
		
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				if section != "" {
					if sectionMap, ok := protocol[section].(map[string]interface{}); ok {
						sectionMap[key] = value
					}
				} else {
					protocol[key] = value
				}
			}
		}
	}
	
	parsed.Data["protocol"] = protocol
}

func parseInterfacesOutput(output string, parsed *ParsedOutput) {
	interfaces := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Interface") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			iface := map[string]interface{}{
				"name":  fields[0],
				"state": fields[1],
				"raw":   line,
			}
			interfaces = append(interfaces, iface)
		}
	}
	
	parsed.Data["interfaces"] = interfaces
}

func parseInterfaceDetailOutput(interfaceName string, output string, parsed *ParsedOutput) {
	iface := map[string]interface{}{
		"name": interfaceName,
		"raw":  output,
	}
	
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "MTU") {
			re := regexp.MustCompile(`MTU (\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 2 {
				if mtu, err := strconv.Atoi(matches[1]); err == nil {
					iface["mtu"] = mtu
				}
			}
		}
	}
	
	parsed.Data["interface"] = iface
}

func parseRoutesOutput(args []string, output string, parsed *ParsedOutput) {
	routes := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "BIRD") || strings.HasPrefix(line, "Table") {
			continue
		}
		
		if strings.Contains(line, "via") || strings.Contains(line, "dev") {
			route := map[string]interface{}{
				"raw": line,
			}
			
			fields := strings.Fields(line)
			if len(fields) > 0 {
				route["prefix"] = fields[0]
			}
			
			routes = append(routes, route)
		}
	}
	
	routeData := map[string]interface{}{
		"routes": routes,
		"count":  len(routes),
	}
	
	if len(args) > 0 {
		routeData["table"] = args[0]
	}
	
	parsed.Data["routes"] = routeData
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

func parseSymbolsOutput(output string, parsed *ParsedOutput) {
	symbols := make(map[string]interface{})
	symbols["raw"] = output
	parsed.Data["symbols"] = symbols
}

func parseOSPFOutput(args []string, output string, parsed *ParsedOutput) {
	ospf := make(map[string]interface{})
	
	if len(args) > 0 {
		ospf["command"] = args[0]
	}
	
	ospf["raw"] = output
	parsed.Data["ospf"] = ospf
}

func parseBGPOutput(args []string, output string, parsed *ParsedOutput) {
	bgp := make(map[string]interface{})
	
	if len(args) > 0 {
		bgp["command"] = args[0]
	}
	
	bgp["raw"] = output
	parsed.Data["bgp"] = bgp
}

func parseBFDOutput(args []string, output string, parsed *ParsedOutput) {
	bfd := make(map[string]interface{})
	
	if len(args) > 0 {
		bfd["command"] = args[0]
	}
	
	bfd["raw"] = output
	parsed.Data["bfd"] = bfd
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
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", p.Timestamp.Format(time.RFC3339)))
	
	if len(p.Data) > 0 {
		sb.WriteString("Parsed Data:\n")
		for key, value := range p.Data {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}
	
	return sb.String()
}
