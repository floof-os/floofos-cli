/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package detector

import (
	"strings"
)

type CommandType int

const (
	Unknown CommandType = iota
	VPP
	BIRD
	FloofOS
)

func (ct CommandType) String() string {
	switch ct {
	case VPP:
		return "VPP"
	case BIRD:
		return "BIRD"
	case FloofOS:
		return "FloofOS"
	default:
		return "Unknown"
	}
}

var vppCommands = []string{
	"show", "set", "clear", "create", "delete", "enable", "disable",
	"api", "binary-api", "cli", "comment", "echo", "exec", "help",
	"history", "log", "loopback", "packet-generator", "punt", "quit",
	"read-file", "script", "service", "time", "trace", "unix",
	"version", "vlib", "vnet", "vpe", "classify", "cop", "feature",
	"flow", "gtpu", "interface", "ip", "ip6", "ipsec", "l2", "lisp",
	"map", "memif", "nat", "pg", "session", "sr", "tap", "vhost",
	"vxlan", "acl", "bond", "bridge", "dhcp", "dns", "flowprobe",
	"gbp", "geneve", "gre", "igmp", "ikev2", "lacp", "lb", "mfib",
	"mpls", "mss", "perfmon", "pppoe", "qos", "rdma", "sctp", "tcp",
	"teib", "udp", "urpf", "vmxnet3", "wireguard",
}

var birdCommands = []string{
	"show", "configure", "enable", "disable", "restart", "reload",
	"down", "up", "debug", "dump", "eval", "filter", "graceful",
	"protocols", "protocol", "interfaces", "interface", "route",
	"routes", "symbols", "memory", "status", "version", "bgp",
	"ospf", "rip", "static", "kernel", "device", "direct", "pipe",
	"radv", "rpki", "babel", "bfd", "graceful restart", "mrtdump",
	"restrict", "unrestrict", "shutdown", "echo", "log", "table",
	"tables", "filter", "function", "template", "import", "export",
	"preference", "multihop", "next hop", "gateway", "metric",
	"community", "confederation", "cluster", "router id", "area",
	"stub", "nssa", "hello", "dead", "retransmit", "priority",
	"cost", "type", "broadcast", "nbma", "pointopoint", "pointomultipoint",
}

var floofOSCommands = []string{
	"backup", "generate", "rollback", "show configuration",
	"config", "pathvector", "service", "system", "network",
	"diagnostics", "monitoring", "logs", "snapshot", "restore",
	"template", "validate", "apply", "diff", "commit", "history",
}

func DetectCommandType(input string) CommandType {
	if input == "" {
		return Unknown
	}

	normalized := strings.ToLower(strings.TrimSpace(input))
	words := strings.Fields(normalized)

	if len(words) == 0 {
		return Unknown
	}

	if isFloofOSCommand(words, normalized) {
		return FloofOS
	}

	if isBIRDCommand(words[0], words) {
		return BIRD
	}

	return VPP
}

func isFloofOSCommand(words []string, fullCommand string) bool {
	if len(words) == 0 {
		return false
	}

	firstWord := words[0]

	if firstWord == "commit" || firstWord == "backup" ||
		firstWord == "rollback" || firstWord == "generate" ||
		firstWord == "restore" {
		return true
	}

	if len(words) >= 2 {
		floofOSPrefixes := []string{
			"show configuration",
			"show running-config",
			"show bgp",
			"show service",
			"show system",
			"set bgp",
			"set hostname",
			"set service",
			"set security",
			"delete service",
			"commit bgp",
		}

		for _, prefix := range floofOSPrefixes {
			if strings.HasPrefix(fullCommand, prefix) {
				return true
			}
		}
	}

	return false
}

func isVPPCommand(firstWord string, words []string) bool {
	for _, cmd := range vppCommands {
		if firstWord == cmd {
			return true
		}
	}

	if len(words) >= 2 {
		secondWord := words[1]
		switch firstWord {
		case "show":
			vppShowCommands := []string{
				"version", "hardware", "runtime", "buffers", "memory",
				"threads", "api", "cli", "errors", "interface", "interfaces",
				"ip", "ip6", "fib", "adj", "arp", "classify", "acl", "nat",
				"session", "trace", "punt", "feature", "node", "graph",
			}
			for _, vppCmd := range vppShowCommands {
				if secondWord == vppCmd {
					return true
				}
			}
		case "set":
			vppSetCommands := []string{
				"interface", "ip", "ip6", "logging", "api-trace", "verbose",
				"node", "punt", "session", "acl", "nat", "feature",
			}
			for _, vppCmd := range vppSetCommands {
				if secondWord == vppCmd {
					return true
				}
			}
		}
	}

	return false
}

func isBIRDCommand(firstWord string, words []string) bool {
	birdOnlyCommands := []string{
		"configure",
		"protocols",
		"protocol",
		"down",
		"up",
		"restart",
		"reload",
	}

	for _, cmd := range birdOnlyCommands {
		if firstWord == cmd {
			return true
		}
	}

	if len(words) >= 2 && firstWord == "show" {
		secondWord := words[1]
		birdShowCommands := []string{
			"protocols",
			"protocol",
			"route",
			"routes",
		}

		for _, birdCmd := range birdShowCommands {
			if secondWord == birdCmd {
				return true
			}
		}
	}

	return false
}

func GetBinaryPath(cmdType CommandType) string {
	switch cmdType {
	case VPP:
		return "vppctl"
	case BIRD:
		return "birdc"
	default:
		return ""
	}
}

func IsHelpRequest(input string) bool {
	trimmed := strings.TrimSpace(input)
	return strings.HasSuffix(trimmed, "?")
}

func GetCommandWithoutHelp(input string) string {
	trimmed := strings.TrimSpace(input)
	if strings.HasSuffix(trimmed, "?") {
		return strings.TrimSpace(trimmed[:len(trimmed)-1])
	}
	return trimmed
}

func IsAmbiguousCommand(input string) bool {
	normalized := strings.ToLower(strings.TrimSpace(input))
	words := strings.Fields(normalized)

	if len(words) < 2 {
		return false
	}

	if isFloofOSCommand(words, normalized) {
		return false
	}

	ambiguousPatterns := []string{
		"show memory",
		"show version",
		"show status",
	}

	twoWords := strings.Join(words[:2], " ")
	for _, pattern := range ambiguousPatterns {
		if twoWords == pattern {
			return true
		}
	}

	return false
}
