/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/floof-os/floofos-cli/internal/readline"
	"github.com/floof-os/floofos-cli/internal/security"
	"github.com/floof-os/floofos-cli/internal/snmp"
	"github.com/floof-os/floofos-cli/internal/system"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/peterh/liner"
	"golang.org/x/term"
)

const useInstantHelp = true

type Mode int

const (
	OperationalMode Mode = iota
	ConfigurationMode
)

type UserPrivilege int

const (
	PrivilegeViewer   UserPrivilege = 5
	PrivilegeOperator UserPrivilege = 10
	PrivilegeAdmin    UserPrivilege = 15
)

type User struct {
	Username  string        `json:"username"`
	Privilege UserPrivilege `json:"privilege"`
	Created   string        `json:"created"`
}

type UserDatabase struct {
	Users []User `json:"users"`
}

type InterfaceStats struct {
	RxBytes       uint64
	TxBytes       uint64
	RxPackets     uint64
	TxPackets     uint64
	Drops         uint64
	Errors        uint64
	LinkSpeedGbps float64
}

const (
	usersFile   = "/etc/floofctl/users.json"
	configDir   = "/etc/floofctl"
	auditLog    = "/var/log/floofctl/audit.log"
	logConfFile = "/etc/floofctl/log.conf"
)

var commandAliases = map[string]string{
	"conf":     "configure",
	"config":   "configure",
	"int":      "interface",
	"adj":      "adjacency",
	"sr":       "segment-routing",
	"route":    "route",
	"backup":   "backups",
	"protocol": "protocols",
	"hardware": "hardware-interfaces",
}

var completionTree = map[string][]string{
	"_root_op": {
		"configure",
		"show",
		"ping",
		"traceroute",
		"system",
		"exit", "end", "quit",
	},
	"_root_config": {
		"backup",
		"commit",
		"create",
		"delete",
		"ping",
		"rollback",
		"set",
		"show",
		"system",
		"traceroute",
		"exit", "end", "quit",
		"clear",
		"enable",
		"disable",
		"test",
		"lcp",
		"linux-cp",
		"restart",
		"down",
		"up",
		"debug",
		"dump",
	},
	"commit": {
		"comment",
	},
	"show": {
		"backups",
		"configuration",
		"log",
		"protocol",
		"resource",
		"system",
		"traffic",
		"users",
		"security",
		"snmp",
		"version",
		"hardware-interfaces",
		"runtime",
		"buffers",
		"memory",
		"threads",
		"api",
		"errors",
		"interface",
		"ip",
		"ip6",
		"linux-cp",
		"bond",
		"bridge", "bridge-domain",
		"vxlan",
		"gre",
		"tap",
		"vhost", "vhost-user",
		"memif",
		"dpdk",
		"pci",
		"cpu",
		"physmem",
		"heap",
		"pools",
		"stats",
		"counters",
		"histogram",
		"node",
		"graph",
		"trace",
		"punt",
		"feature",
		"workers",
		"clock",
		"time",
		"logging",
		"nat",
		"acl",
		"classify",
		"arp",
		"fib",
		"adjacency",
		"bfd",
		"ipsec",
		"ikev2",
		"wireguard",
		"segment-routing",
		"mpls",
		"policer",
		"qos",
		"flow",
		"flowprobe",
		"perfmon",
		"plugins",
		"l2fib",
		"l2fwd",
		"ethernet",
		"protocols",
		"route",
		"ospf",
		"rip",
		"static",
		"kernel",
		"babel",
		"rpki",
		"status",
		"symbols",
		"tables",
		"filter",
		"functions",
	},
	"show interface": {
		"addr",
		"rx-placement",
		"rx-mode",
	},
	"show hardware-interfaces": {},
	"show runtime":             {},
	"show buffers":             {},
	"show node":                {},
	"show dpdk": {
		"buffer",
		"version",
		"physmem",
	},
	"show ip": {
		"fib",
		"mfib",
		"neighbor",
		"neighbors",
	},
	"show ip fib":       {},
	"show ip mfib":      {},
	"show ip neighbor":  {},
	"show ip neighbors": {},
	"show ip6": {
		"fib",
		"mfib",
		"neighbor",
		"neighbors",
	},
	"show ip6 fib":       {},
	"show ip6 mfib":      {},
	"show ip6 neighbor":  {},
	"show ip6 neighbors": {},
	"show nat": {
		"sessions",
		"users",
		"interfaces",
		"static",
		"pools",
	},
	"show acl": {
		"index",
		"lookup",
		"applied",
	},
	"show lcp":           {},
	"show bond":          {},
	"show bridge-domain": {},
	"show bfd":           {},
	"show ipsec": {
		"sa",
		"spd",
		"tunnel",
		"all",
		"backends",
		"interface",
		"protect",
	},
	"show mpls": {
		"fib",
		"interface",
	},
	"show vxlan": {
		"tunnel",
	},
	"show protocols": {
		"all",
	},
	"show route": {
		"all",
		"count",
		"export",
		"filter",
		"for",
		"import",
		"primary",
		"protocol",
		"table",
		"where",
	},
	"show route protocol": {},
	"show route table":    {},
	"show ospf":           {},
	"show symbols":        {},
	"system": {
		"install",
		"reboot",
	},
	"set system ntp": {
		"server",
	},
	"show system": {
		"time",
		"logging",
		"commit",
	},
	"show system logging": {
		"last",
		"user",
		"config",
		"commit",
		"today",
	},
	"show protocol": {
		"bgp",
	},
	"show protocol bgp": {
		"summary",
		"logging",
	},
	"show protocol bgp logging": {
		"last",
	},
	"show traffic": {
		"interface",
	},
	"show security": {
		"firewall",
		"fail2ban",
		"ssh-keys",
		"ssh-config",
		"rate-limit",
	},
	"show security firewall": {
		"status",
		"rules",
	},
	"show security fail2ban": {
		"status",
		"banned",
	},
	"show snmp": {
		"status",
		"config",
		"statistics",
	},
	"set": {
		"hostname",
		"all",
		"protocol",
		"system",
		"security",
		"snmp",
		"interface",
		"ip",
		"ip6",
		"logging",
	},
	"set protocol": {
		"bgp",
	},
	"set interface": {
		"state",
		"ip",
		"ip6",
		"mac",
		"mtu",
		"promiscuous",
		"rx-mode",
		"rx-placement",
		"tx-queue",
		"up",
		"down",
	},
	"set interface state": {},
	"set interface ip": {
		"address",
		"table",
	},
	"set interface ip6": {
		"address",
		"table",
	},
	"set interface rx-mode": {
		"polling",
		"interrupt",
		"adaptive",
	},
	"set interface rx-placement": {
		"queue",
		"worker",
	},
	"set ip": {
		"neighbor",
		"punt",
		"local",
		"table",
		"route",
		"adjacency",
	},
	"set ip6": {
		"neighbor",
		"punt",
		"local",
		"table",
		"route",
		"adjacency",
	},
	"set logging": {
		"level",
		"class",
		"unthrottle",
		"size",
	},
	"set logging level": {
		"emerg",
		"alert",
		"crit",
		"err",
		"warn",
		"notice",
		"info",
		"debug",
		"disabled",
	},
	"set all": {
		"logging",
	},
	"set all logging": {
		"enable",
		"disable",
	},
	"set system": {
		"time-zone",
		"ntp",
		"clock",
		"logging",
	},
	"set system logging": {
		"enable",
		"disable",
	},
	"set protocol bgp": {
		"logging",
	},
	"set protocol bgp logging": {
		"enable",
		"disable",
	},
	"set security": {
		"firewall",
		"fail2ban",
		"ssh-key",
		"ssh-password-auth",
		"rate-limit",
	},
	"set security firewall": {
		"enable",
		"disable",
		"rule",
	},
	"set security firewall rule": {
		"<name>",
	},
	"set security fail2ban": {
		"enable",
		"disable",
		"maxretry",
		"bantime",
		"jail",
	},
	"set security ssh-password-auth": {
		"enable",
		"disable",
	},
	"set snmp": {
		"enable",
		"disable",
		"community",
		"location",
		"contact",
		"polling-interval",
	},
	"create": {
		"user",
		"loopback",
		"bridge-domain",
		"bond",
		"vxlan",
		"gre",
		"tap",
		"vhost",
		"vhost-user",
		"memif",
		"sub-interface",
	},
	"create user": {
		"password",
	},
	"create loopback":      {},
	"create bridge-domain": {},
	"create bond":          {},
	"create vxlan":         {},
	"create gre":           {},
	"create tap":           {},
	"create vhost-user":    {},
	"create memif":         {},
	"delete": {
		"user",
		"security",
		"loopback",
		"bridge-domain",
		"bond",
		"vxlan",
		"gre",
		"tap",
		"vhost-user",
		"memif",
		"sub-interface",
	},
	"delete loopback":      {},
	"delete bridge-domain": {},
	"delete bond":          {},
	"delete vxlan":         {},
	"delete gre":           {},
	"delete tap":           {},
	"delete vhost-user":    {},
	"delete memif":         {},
	"delete security": {
		"firewall",
		"ssh-key",
	},
	"delete security firewall": {
		"rule",
	},
	"clear": {
		"counters",
		"errors",
		"hardware",
		"interface",
		"runtime",
		"trace",
		"nat",
		"session",
		"acl",
		"logging",
	},
	"enable":  {},
	"disable": {},
	"test": {
		"heap-validate",
		"papi",
		"adjacency",
		"bundle",
		"classify",
		"counter",
		"dhcp",
		"fib",
		"flow",
		"ip",
		"ip6",
		"l2",
		"lcp",
		"map",
		"mpcap",
		"node",
		"pg",
		"physmem",
		"punt",
		"session",
		"stats",
		"tcp",
		"udp",
		"vlib",
		"vpe",
	},
	"lcp": {
		"create",
		"delete",
	},
	"restart": {},
	"down":    {},
	"up":      {},
	"debug": {
		"protocols",
		"channels",
		"interfaces",
		"events",
		"packets",
		"filters",
		"states",
		"routes",
		"all",
		"off",
	},
	"debug protocols": {},
	"dump": {
		"protocols",
		"tables",
		"neighbors",
		"attributes",
		"routes",
		"filters",
		"interfaces",
	},
	"backup": {
		"export",
		"import",
	},
	"backup export": {
		"<name>",
		"path",
	},
	"backup import": {
		"<name>",
		"path",
	},
}

var currentMode = OperationalMode
var currentHostname = ""
var hasUnsavedChanges = false
var currentUser *User

func initAuditLog() error {
	logDir := "/var/log/floofctl"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	f.Close()

	return nil
}

func auditLogWrite(level, message string) {
	f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}

	logLine := fmt.Sprintf("%s [%s] %s: %s\n", timestamp, level, username, message)
	f.WriteString(logLine)
}

func auditLogInfo(message string) {
	auditLogWrite("INFO", message)
}

func auditLogCmd(command string) {
	auditLogWrite("CMD", command)
}

func auditLogConfig(command string) {
	auditLogWrite("CONFIG", command)
}

func auditLogCommit(message string) {
	auditLogWrite("COMMIT", message)
}

func auditLogWarn(message string) {
	auditLogWrite("WARN", message)
}

func auditLogError(message string) {
	auditLogWrite("ERROR", message)
}

func redactPassword(command string) string {
	if strings.Contains(command, "password") {
		parts := strings.Fields(command)
		for i, part := range parts {
			if part == "password" && i+1 < len(parts) {
				parts[i+1] = "******"
			}
		}
		return strings.Join(parts, " ")
	}
	return command
}

func main() {
	if err := initAuditLog(); err != nil {
		fmt.Printf("Warning: Could not initialize audit log: %v\n", err)
	}

	loadHostname()

	var err error
	currentUser, err = getCurrentUserInfo()
	if err != nil {
		fmt.Printf("Warning: Could not load user info: %v\n", err)
		auditLogWarn(fmt.Sprintf("Failed to load user info: %v", err))
	} else {
		auditLogInfo("Logged in")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigChan {
		}
	}()

	white := "\033[37m"
	yellow := "\033[33m"
	reset := "\033[0m"

	fmt.Println(white + "   ______          ___ ____  ____" + reset)
	fmt.Println(white + "  / __/ /__  ___  / _// __ \\/ __/" + reset)
	fmt.Println(white + " / _// / _ \\/ _ \\/ _// /_/ /\\ \\  " + reset)
	fmt.Println(white + "/_/ /_/\\___/\\___/_/  \\____/___/  " + reset)
	fmt.Println()
	fmt.Println(white + "[ Fast Line-rate Offload On Fabric OS ]" + reset)
	fmt.Println(white + "https://floofos.io | Copyright (c) 2025" + reset)
	fmt.Println()
	fmt.Println(yellow + "Type ? for context help" + reset)
	fmt.Println()

	if err := system.RunFirstBootSetup(); err != nil {
		fmt.Printf("Warning: First boot setup error: %v\n", err)
	}

	if useInstantHelp {
		runWithInstantHelp()
		return
	}

	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)

	line.SetCompleter(func(currentLine string) []string {
		return completer(currentLine)
	})

	line.SetTabCompletionStyle(liner.TabPrints)

	for {
		prompt := getPrompt()

		input, err := line.Prompt(prompt)
		if err == liner.ErrPromptAborted {
			fmt.Println()
			continue
		} else if err == io.EOF {
			fmt.Println()
			break
		} else if err != nil {
			line.Close()
			line = liner.NewLiner()
			line.SetCtrlCAborts(true)
			line.SetCompleter(func(currentLine string) []string {
				return completer(currentLine)
			})
			line.SetTabCompletionStyle(liner.TabPrints)
			continue
		}

		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if strings.HasSuffix(input, " ?") || input == "?" {
			baseCmd := strings.TrimSuffix(input, " ?")
			baseCmd = strings.TrimSpace(baseCmd)
			if baseCmd != "" {
				line.AppendHistory(input)
				line.AppendHistory(baseCmd)
			} else {
				line.AppendHistory(input)
			}
		} else {
			line.AppendHistory(input)
		}

		auditLogCmd(redactPassword(input))

		needRestart := processCommand(input, line)
		if needRestart {
			line = liner.NewLiner()
			line.SetCtrlCAborts(true)
			line.SetCompleter(func(currentLine string) []string {
				return completer(currentLine)
			})
			line.SetTabCompletionStyle(liner.TabPrints)
		}
	}

	line.Close()
}

func runWithInstantHelp() {
	rl := readline.New()
	defer rl.Close()

	rl.SetHelpHandler(func(line string) {
		showHelp(line + " ?")
	})

	rl.SetCompleteHandler(func(line string) []string {
		return completer(line)
	})

	for {
		rl.SetPrompt(getPrompt())

		input, err := rl.Readline()
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println()
				break
			}
			continue
		}

		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if strings.HasSuffix(input, " ?") || input == "?" {
			continue
		}

		auditLogCmd(redactPassword(input))

		needRestart := processCommandInstantHelp(input)
		if needRestart {
			continue
		}
	}
}

func processCommandInstantHelp(input string) bool {
	args := strings.Fields(input)
	if len(args) == 0 {
		return false
	}

	cmd := strings.ToLower(args[0])

	if cmd == "exit" || cmd == "end" || cmd == "quit" {
		if currentMode == ConfigurationMode {
			currentMode = OperationalMode
			fmt.Println("Exiting configuration mode")
			return false
		}
		if currentUser != nil && currentUser.Username == "root" {
			fmt.Print("Exit to shell? (Y/N): ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToUpper(response))
			if response == "Y" || response == "YES" {
				fmt.Println("Exiting FloofCTL CLI")
				auditLogInfo("Logged out")
				os.Exit(0)
			}
			return false
		}
		fmt.Println("Non-root users cannot exit to shell")
		return false
	}

	if cmd == "configure" || cmd == "conf" || cmd == "config" {
		if currentMode == OperationalMode {
			currentMode = ConfigurationMode
			fmt.Println("Entering configuration mode")
		}
		return false
	}

	if cmd == "system" && len(args) >= 2 && args[1] == "install" {
		if currentMode == OperationalMode {
			fmt.Println("Error: Enter configuration mode first")
			return false
		}
		if currentUser != nil && currentUser.Privilege < PrivilegeAdmin {
			fmt.Println("Error: Admin privilege required")
			return false
		}
		err := system.RunInstall()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		return true
	}

	if cmd == "system" && len(args) >= 2 && args[1] == "reboot" {
		fmt.Print("Reboot system? (Y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToUpper(response))
		if response == "Y" || response == "YES" {
			fmt.Println("Rebooting...")
			exec.Command("systemctl", "reboot").Run()
		}
		return false
	}

	if currentMode == OperationalMode && cmd != "show" && cmd != "configure" && cmd != "help" && cmd != "ping" && cmd != "traceroute" && cmd != "system" {
		fmt.Println("Error: Only 'show' commands allowed in operational mode")
		return false
	}

	if cmd == "ping" {
		executePing(args)
		return false
	}

	if cmd == "traceroute" {
		executeTraceroute(args)
		return false
	}

	if cmd == "help" {
		showHelp("")
		return false
	}

	if cmd == "show" && len(args) == 1 {
		showConfiguration()
		return false
	}

	if len(args) >= 3 && args[0] == "show" && args[1] == "protocol" && args[2] == "bgp" {
		if len(args) >= 4 && args[3] == "logging" {
			showBGPLog(args[4:])
			return false
		}
		if len(args) >= 4 && args[3] == "summary" {
			executePathvector([]string{"bgp", "summary"})
			return false
		}
		executePathvector([]string{"bgp"})
		return false
	}

	line := strings.Join(args, " ")

	if cmd == "system" || (len(args) >= 3 && args[0] == "set" && args[1] == "system") || (len(args) >= 3 && args[0] == "show" && args[1] == "system" && args[2] == "time") {
		handleSystemCommandsInstantHelp(line)
		return false
	}

	if cmd == "dns" && len(args) >= 2 && args[1] == "name-server" {
		handleDNSCommand(args)
		return false
	}

	if isBIRDCommand(line) {
		executeBIRD(args)
	} else if isFloofOSCommand(line) {
		executeFloofOS(line)
	} else {
		executeVPP(args)
	}
	return false
}

func completer(line string) []string {
	words := strings.Fields(line)

	var rootKey string
	if currentMode == OperationalMode {
		rootKey = "_root_op"
	} else {
		rootKey = "_root_config"
	}

	if len(words) == 0 {
		return completionTree[rootKey]
	}

	var contextKey string
	var prefix string
	var prefixWords []string

	if len(words) == 1 {
		contextKey = rootKey
		prefix = words[0]
		prefixWords = []string{}
	} else {
		for i := len(words) - 1; i >= 1; i-- {
			tryKey := strings.Join(words[:i], " ")
			if _, exists := completionTree[tryKey]; exists {
				contextKey = tryKey
				prefix = words[len(words)-1]
				prefixWords = words[:len(words)-1]
				break
			}
		}

		if contextKey == "" {
			if _, exists := completionTree[words[0]]; exists {
				contextKey = words[0]
				prefix = words[len(words)-1]
				prefixWords = words[:len(words)-1]
			} else {
				return nil
			}
		}
	}

	candidates, exists := completionTree[contextKey]
	if !exists {
		return nil
	}

	var matches []string
	for _, cmd := range candidates {
		if strings.HasPrefix(strings.ToLower(cmd), strings.ToLower(prefix)) {
			if len(prefixWords) > 0 {
				fullCompletion := strings.Join(prefixWords, " ") + " " + cmd
				matches = append(matches, fullCompletion)
			} else {
				matches = append(matches, cmd)
			}
		}
	}

	if len(matches) == 1 && !strings.HasSuffix(matches[0], " ") {
		matches[0] = matches[0] + " "
	}

	return matches
}

func getPrompt() string {
	hostname := currentHostname
	if hostname == "" {
		hostname = "floof"
	}

	if currentMode == ConfigurationMode {
		return hostname + "(config)# "
	}
	return hostname + "> "
}

func processCommand(line string, liner *liner.State) bool {
	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	cmd := args[0]

	isFloofOSHelp := false
	if strings.HasSuffix(line, " ?") {
		if (cmd == "rollback" && len(args) == 2 && args[1] == "?") ||
			(cmd == "backup" && len(args) == 3 && args[1] == "restore" && args[2] == "?") {
			isFloofOSHelp = true
		}
	}

	if !isFloofOSHelp && (strings.HasSuffix(line, " ?") || line == "?") {
		showHelp(line)
		return false
	}

	switch cmd {
	case "configure", "conf", "config":
		if currentMode == OperationalMode {
			currentMode = ConfigurationMode
			auditLogInfo("Entered configuration mode")
		}
		return false

	case "exit", "end", "quit":
		if currentMode == ConfigurationMode {
			if hasUnsavedChanges {
				fmt.Print("You have unsaved configuration. Commit before exit? (Y/N/Cancel): ")

				response, err := liner.Prompt("")
				if err != nil {
					fmt.Println("Error reading input, staying in config mode")
					return false
				}

				response = strings.TrimSpace(strings.ToUpper(response))

				if response == "Y" || response == "YES" {
					fmt.Println("Committing configuration...")
					executeFloofOS("commit")
					hasUnsavedChanges = false
					fmt.Println("Returning to operational mode")
					currentMode = OperationalMode
					return false
				} else if response == "N" || response == "NO" {
					fmt.Println("Configuration changes discarded")
					hasUnsavedChanges = false
					currentMode = OperationalMode
					return false
				} else {
					fmt.Println("Cancelled. Staying in configuration mode")
					return false
				}
			}

			currentMode = OperationalMode
			auditLogInfo("Exited configuration mode")
			return false
		} else {
			fmt.Println("Note: Non-root users will disconnect from SSH session.")
			fmt.Print("Exit to Linux shell? (Y/N): ")

			response, err := liner.Prompt("")
			if err != nil {
				fmt.Println("Error reading input, staying in CLI")
				return false
			}

			response = strings.TrimSpace(strings.ToUpper(response))
			if response == "Y" || response == "YES" {
				fmt.Println("Exiting FloofCTL CLI")
				fmt.Println("To re-enter CLI, type 'cli'")
				fmt.Println()
				auditLogInfo("Logged out")
				liner.Close()
				os.Exit(0)
			}

			fmt.Println()
			return false
		}

	case "help":
		showHelp("")
		return false
	}

	if cmd == "system" && len(args) >= 2 && args[1] == "install" {
		if currentMode == OperationalMode {
			fmt.Println("Error: 'system install' requires configuration mode")
			fmt.Println("Use 'configure' to enter configuration mode first")
			return false
		}
		if currentUser.Privilege < PrivilegeAdmin {
			fmt.Println("Error: Admin privilege required for system installation")
			return false
		}
		liner.Close()
		err := system.RunInstall()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		return true
	}

	if currentMode == OperationalMode && cmd != "show" && cmd != "configure" && cmd != "help" && cmd != "ping" && cmd != "traceroute" && cmd != "system" {
		fmt.Println("Error: Only 'show' commands allowed in operational mode")
		fmt.Println("Use 'configure' to enter configuration mode")
		return false
	}

	if cmd == "ping" {
		executePing(args)
		return false
	}

	if cmd == "traceroute" {
		executeTraceroute(args)
		return false
	}

	if len(args) >= 3 && args[0] == "show" && args[1] == "protocol" && args[2] == "bgp" {
		if len(args) >= 4 && args[3] == "logging" {
			return false
		}
		executePathvector(args[2:])
		return false
	}

	if args[0] == "system" || (len(args) >= 3 && args[0] == "set" && args[1] == "system") || (len(args) >= 3 && args[0] == "show" && args[1] == "system" && args[2] == "time") {
		handleSystemCommands(line, liner)
		return false
	}

	if args[0] == "dns" && len(args) >= 2 && args[1] == "name-server" {
		handleDNSCommand(args)
		return false
	}

	if isBIRDCommand(line) {
		executeBIRD(args)
	} else if isFloofOSCommand(line) {
		executeFloofOS(line)
	} else {
		executeVPP(args)
	}

	return false
}

func showHelp(line string) {
	baseCmd := strings.TrimSpace(strings.TrimSuffix(line, "?"))
	baseCmd = strings.TrimSpace(baseCmd)

	if baseCmd != "" {
		args := strings.Fields(baseCmd)

		if len(args) == 1 && args[0] == "set" {
			var output strings.Builder
			output.WriteString("Possible completions:\n")
			output.WriteString("  all           Global configuration\n")
			output.WriteString("  hostname      System hostname\n")
			output.WriteString("  protocol      Routing protocol configuration\n")
			output.WriteString("  security [ firewall | fail2ban | ssh-key ]\n")
			output.WriteString("                Security and access control\n")
			output.WriteString("  snmp [ enable | community | location ]\n")
			output.WriteString("                SNMP monitoring agent\n")
			output.WriteString("  system        System configuration\n")
			vppCmd := exec.Command("vppctl", "set", "?")
			if vppOutput, err := vppCmd.CombinedOutput(); err == nil && len(vppOutput) > 0 {
				vppStr := strings.TrimSpace(string(vppOutput))
				if vppStr != "" {
					output.WriteString(vppStr)
					output.WriteString("\n")
				}
			}
			printWithPager(output.String())
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "all" {
			fmt.Println("  logging       Logging control")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "all" && args[2] == "logging" {
			fmt.Println("Possible completions:")
			fmt.Println("  disable       Disable all logging systems")
			fmt.Println("  enable        Enable all logging systems")
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "security" {
			fmt.Println("Possible completions:")
			fmt.Println("  firewall [ enable | disable | rule ]")
			fmt.Println("                Firewall configuration (nftables)")
			fmt.Println("  fail2ban [ enable | disable | maxretry ]")
			fmt.Println("                Intrusion prevention system")
			fmt.Println("  ssh-key <username> key <public-key>")
			fmt.Println("                SSH public key authentication")
			fmt.Println("  ssh-password-auth [ enable | disable ]")
			fmt.Println("                Password authentication control")
			fmt.Println("  rate-limit ssh <connections-per-minute>")
			fmt.Println("                SSH connection rate limiting")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" {
			fmt.Println("Possible completions:")
			fmt.Println("  enable                           Enable firewall")
			fmt.Println("  disable                          Disable firewall")
			fmt.Println("  rule <name> protocol <tcp|udp> port <port> [src-address <ip/cidr>] action <accept|drop>")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" && args[3] == "enable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Enable firewall")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" && args[3] == "disable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Disable firewall")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" && args[3] == "rule" {
			fmt.Println("Possible completions:")
			fmt.Println("  <name>        Unique rule name")
			return
		}

		if len(args) >= 5 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" && args[3] == "rule" {
			fmt.Println("Usage: set security firewall rule <name> protocol <tcp|udp> port <port> [src-address <ip/cidr>] action <accept|drop>")
			fmt.Println()
			fmt.Println("Parameters:")
			fmt.Println("  protocol      tcp or udp")
			fmt.Println("  port          Port number (1-65535)")
			fmt.Println("  src-address   Source IP/CIDR (optional)")
			fmt.Println("  action        accept or drop")
			fmt.Println()
			fmt.Println("Examples:")
			fmt.Println("  set security firewall rule web protocol tcp port 80 action accept")
			fmt.Println("  set security firewall rule ssh-lan protocol tcp port 22 src-address 192.168.1.0/24 action accept")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" {
			fmt.Println("Possible completions:")
			fmt.Println("  enable                    Enable fail2ban")
			fmt.Println("  disable                   Disable fail2ban")
			fmt.Println("  maxretry <number>         Maximum retry attempts (default: 3)")
			fmt.Println("  bantime <seconds>         Ban duration in seconds (default: 600)")
			fmt.Println("  jail <name> [enable|disable]")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "enable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Enable fail2ban")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "disable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Disable fail2ban")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "maxretry" {
			fmt.Println("Possible completions:")
			fmt.Println("  <number>      Maximum login attempts before ban")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "bantime" {
			fmt.Println("Possible completions:")
			fmt.Println("  <seconds>     Ban duration in seconds")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "ssh-key" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Username to add SSH key for")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "ssh-password-auth" {
			fmt.Println("Possible completions:")
			fmt.Println("  enable        Enable SSH password authentication")
			fmt.Println("  disable       Disable SSH password authentication")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "firewall" && args[3] == "rule" {
			fmt.Println("Possible completions:")
			fmt.Println("  <name>        Unique rule name")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "maxretry" {
			fmt.Println("Possible completions:")
			fmt.Println("  <number>      Maximum login attempts before ban (default: 3)")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "security" && args[2] == "fail2ban" && args[3] == "bantime" {
			fmt.Println("Possible completions:")
			fmt.Println("  <seconds>     Ban duration in seconds (default: 600)")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "ssh-key" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Username to add SSH key for")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "security" && args[2] == "ssh-password-auth" {
			fmt.Println("Possible completions:")
			fmt.Println("  enable        Enable SSH password authentication")
			fmt.Println("  disable       Disable SSH password authentication")
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "snmp" {
			fmt.Println("Possible completions:")
			fmt.Println("  community <string>")
			fmt.Println("                SNMP community string (read-only)")
			fmt.Println("  contact <email>")
			fmt.Println("                System contact email")
			fmt.Println("  enable        Enable SNMP agent")
			fmt.Println("  disable       Disable SNMP agent")
			fmt.Println("  location <string>")
			fmt.Println("                Physical location description")
			fmt.Println("  polling-interval <seconds>")
			fmt.Println("                VPP stats polling interval (default: 30)")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "enable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Enable SNMP agent")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "disable" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Disable SNMP agent")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "community" {
			fmt.Println("Possible completions:")
			fmt.Println("  <string>      SNMP community string")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "location" {
			fmt.Println("Possible completions:")
			fmt.Println("  <string>      Physical location description")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "contact" {
			fmt.Println("Possible completions:")
			fmt.Println("  <email>       System contact email")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "polling-interval" {
			fmt.Println("Possible completions:")
			fmt.Println("  <seconds>     VPP stats polling interval")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "community" {
			fmt.Println("Possible completions:")
			fmt.Println("  <string>      SNMP community string for read-only access")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "location" {
			fmt.Println("Possible completions:")
			fmt.Println("  <string>      Physical location description")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "contact" {
			fmt.Println("Possible completions:")
			fmt.Println("  <email>       System contact email address")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "snmp" && args[2] == "polling-interval" {
			fmt.Println("Possible completions:")
			fmt.Println("  <seconds>     VPP stats polling interval (default: 30)")
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "protocol" {
			fmt.Println("Possible completions:")
			fmt.Println("  bgp           BGP routing protocol")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "protocol" && args[2] == "bgp" {
			fmt.Println("  <cr>          Edit BGP configuration")
			fmt.Println("  logging       BGP log viewer control")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "protocol" && args[2] == "bgp" && args[3] == "logging" {
			fmt.Println("  disable       Disable BGP log viewer")
			fmt.Println("  enable        Enable BGP log viewer")
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "hostname" {
			fmt.Println("Possible completions:")
			fmt.Println("  <hostname>    New hostname for this router")
			return
		}

		if len(args) == 2 && args[0] == "set" && args[1] == "system" {
			fmt.Println("Possible completions:")
			fmt.Println("  clock         Manual time configuration")
			fmt.Println("  logging       Audit log control")
			fmt.Println("  ntp           NTP server configuration")
			fmt.Println("  time-zone     Timezone configuration")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "system" && args[2] == "time-zone" {
			fmt.Println("Possible completions:")
			fmt.Println("  <timezone>    Timezone (e.g., Asia/Jakarta, UTC)")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "system" && args[2] == "clock" {
			fmt.Println("Possible completions:")
			fmt.Println("  <time>        Time in format YYYY-MM-DD HH:MM:SS")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "system" && args[2] == "logging" {
			fmt.Println("  disable       Disable audit logging")
			fmt.Println("  enable        Enable audit logging")
			return
		}

		if len(args) == 3 && args[0] == "set" && args[1] == "system" && args[2] == "ntp" {
			fmt.Println("Possible completions:")
			fmt.Println("  server        Add NTP server")
			return
		}

		if len(args) == 4 && args[0] == "set" && args[1] == "system" && args[2] == "ntp" && args[3] == "server" {
			fmt.Println("Possible completions:")
			fmt.Println("  <hostname>    NTP server address (e.g., pool.ntp.org)")
			return
		}

		if len(args) == 1 && args[0] == "show" {
			var output strings.Builder
			output.WriteString("  <cr>          Display current configuration\n")
			output.WriteString("  backups       Show all backups\n")
			output.WriteString("  configuration Current configuration\n")
			output.WriteString("  protocol      Routing protocol information\n")
			output.WriteString("  resource      System resources\n")
			output.WriteString("  security      Security and access control\n")
			output.WriteString("  snmp          SNMP agent status\n")
			output.WriteString("  system        System information\n")
			output.WriteString("  traffic       Interface traffic\n")
			output.WriteString("  users         CLI users\n")
			vppCmd := exec.Command("vppctl", "show", "?")
			if vppOutput, err := vppCmd.CombinedOutput(); err == nil && len(vppOutput) > 0 {
				vppStr := strings.TrimSpace(string(vppOutput))
				if vppStr != "" {
					output.WriteString(vppStr)
					output.WriteString("\n")
				}
			}

			printWithPager(output.String())
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "protocol" {
			fmt.Println("Possible completions:")
			fmt.Println("  bgp           BGP routing protocol")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "protocol" && args[2] == "bgp" {
			fmt.Println("  <cr>          BGP status")
			fmt.Println("  logging       BGP routing logs")
			fmt.Println("  summary       BGP summary")
			return
		}

		if len(args) == 4 && args[0] == "show" && args[1] == "protocol" && args[2] == "bgp" && args[3] == "logging" {
			fmt.Println("  <cr>          Show last 100 lines")
			fmt.Println("  last          Show last N lines")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "system" {
			fmt.Println("  <cr>          System information")
			fmt.Println("  commit        Commit history")
			fmt.Println("  logging       Audit logs")
			fmt.Println("  time          Date, time, timezone, NTP")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "system" && args[2] == "logging" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show last 50 lines")
			fmt.Println("  commit        Commit logs")
			fmt.Println("  config        Configuration logs")
			fmt.Println("  last          Show last N lines")
			fmt.Println("  today         Today's logs")
			fmt.Println("  user          Filter by user")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "system" && args[2] == "commit" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show commit history")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "system" && args[2] == "time" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show current time and timezone")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "traffic" && args[2] == "interface" {
			fmt.Println("Possible completions:")
			fmt.Println("  <interface>   Interface name for traffic monitoring")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "system" && args[2] == "commit" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show commit history")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "system" && args[2] == "time" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show current time and timezone")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "traffic" && args[2] == "interface" {
			fmt.Println("Possible completions:")
			fmt.Println("  <interface>   Interface name for traffic monitoring")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "security" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          All security settings")
			fmt.Println("  firewall [ status | rules ]")
			fmt.Println("                Firewall configuration and status")
			fmt.Println("  fail2ban [ status | banned ]")
			fmt.Println("                Intrusion prevention status")
			fmt.Println("  ssh-keys      SSH public keys")
			fmt.Println("  ssh-config    SSH daemon configuration")
			fmt.Println("  rate-limit    Connection rate limiting")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "security" && args[2] == "firewall" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Firewall status")
			fmt.Println("  status        Service status and statistics")
			fmt.Println("  rules         Active firewall rules")
			return
		}

		if len(args) == 3 && args[0] == "show" && args[1] == "security" && args[2] == "fail2ban" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Fail2ban status")
			fmt.Println("  status        Service status and jails")
			fmt.Println("  banned        Currently banned IP addresses")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "snmp" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          SNMP status")
			fmt.Println("  status        Agent status and uptime")
			fmt.Println("  config        Current configuration")
			fmt.Println("  statistics    Query statistics")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "traffic" {
			fmt.Println("Possible completions:")
			fmt.Println("  interface     Real-time interface traffic monitoring")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "users" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          List all CLI users")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "backups" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          List all configuration backups")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "resource" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          System resource utilization")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "configuration" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Display current configuration")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "log" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show VPP log")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "logging" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show VPP logging configuration")
			return
		}

		if len(args) == 2 && args[0] == "show" && args[1] == "version" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Show FloofOS and VPP version")
			return
		}

		if len(args) == 1 && args[0] == "commit" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Commit configuration")
			fmt.Println("  comment       Add commit comment")
			return
		}

		if len(args) == 2 && args[0] == "commit" && args[1] == "comment" {
			fmt.Println("Possible completions:")
			fmt.Println("  <comment>     Commit description")
			return
		}

		if len(args) == 1 && args[0] == "delete" {
			var output strings.Builder
			output.WriteString("Possible completions:\n")
			output.WriteString("  user <username>\n")
			output.WriteString("                Delete CLI user\n")
			output.WriteString("  security [ firewall | ssh-key ]\n")
			output.WriteString("                Delete security configurations\n")
			vppCmd := exec.Command("vppctl", "delete", "?")
			if vppOutput, err := vppCmd.CombinedOutput(); err == nil && len(vppOutput) > 0 {
				vppStr := strings.TrimSpace(string(vppOutput))
				if vppStr != "" {
					output.WriteString(vppStr)
					output.WriteString("\n")
				}
			}
			printWithPager(output.String())
			return
		}

		if len(args) == 2 && args[0] == "delete" && args[1] == "user" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Username to delete")
			return
		}

		if len(args) == 2 && args[0] == "delete" && args[1] == "user" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Username to delete")
			return
		}

		if len(args) == 2 && args[0] == "delete" && args[1] == "security" {
			fmt.Println("Possible completions:")
			fmt.Println("  firewall rule <name>")
			fmt.Println("                Delete firewall rule")
			fmt.Println("  ssh-key <username>")
			fmt.Println("                Delete SSH public key")
			return
		}

		if len(args) == 3 && args[0] == "delete" && args[1] == "security" && args[2] == "firewall" {
			fmt.Println("Possible completions:")
			fmt.Println("  rule <name>   Delete firewall rule by name")
			return
		}

		if len(args) == 3 && args[0] == "delete" && args[1] == "security" && args[2] == "ssh-key" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Delete SSH key for user")
			return
		}

		if len(args) == 3 && args[0] == "delete" && args[1] == "security" && args[2] == "firewall" {
			fmt.Println("Possible completions:")
			fmt.Println("  rule <name>   Delete firewall rule by name")
			return
		}

		if len(args) == 3 && args[0] == "delete" && args[1] == "security" && args[2] == "ssh-key" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Delete SSH key for user")
			return
		}

		if len(args) == 1 && args[0] == "backup" {
			fmt.Println("Possible completions:")
			fmt.Println("  export <name> [path <path>]")
			fmt.Println("                Export backup as .tar.gz")
			fmt.Println("  import <name> [path <path>]")
			fmt.Println("                Import backup from .tar.gz")
			return
		}

		if len(args) == 2 && args[0] == "backup" && args[1] == "export" {
			fmt.Println("Possible completions:")
			fmt.Println("  <name>        Backup name")
			fmt.Println("  path          Custom export path")
			return
		}

		if len(args) == 2 && args[0] == "backup" && args[1] == "import" {
			fmt.Println("Possible completions:")
			fmt.Println("  <name>        Backup name to import")
			fmt.Println("  path          Custom import path")
			return
		}

		if len(args) == 1 && args[0] == "rollback" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Rollback to previous commit")
			fmt.Println("  <0-49>        Rollback to specific commit number")
			return
		}

		if len(args) == 1 && args[0] == "system" {
			fmt.Println("Possible completions:")
			fmt.Println("  reboot        Reboot the system")
			return
		}

		if len(args) == 2 && args[0] == "system" && args[1] == "reboot" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Reboot the system")
			return
		}

		if len(args) == 1 && args[0] == "create" {
			var output strings.Builder
			output.WriteString("Possible completions:\n")
			output.WriteString("  user <username> password <password> [ssh-key <key>]\n")
			output.WriteString("                Create new CLI user with optional SSH key\n")
			vppCmd := exec.Command("vppctl", "create", "?")
			if vppOutput, err := vppCmd.CombinedOutput(); err == nil && len(vppOutput) > 0 {
				vppStr := strings.TrimSpace(string(vppOutput))
				if vppStr != "" {
					output.WriteString(vppStr)
					output.WriteString("\n")
				}
			}
			printWithPager(output.String())
			return
		}

		if len(args) == 2 && args[0] == "create" && args[1] == "user" {
			fmt.Println("Possible completions:")
			fmt.Println("  <username>    Username for new CLI user")
			return
		}

		if len(args) == 3 && args[0] == "create" && args[1] == "user" {
			fmt.Println("Possible completions:")
			fmt.Println("  password      Set password for user")
			return
		}

		if len(args) == 4 && args[0] == "create" && args[1] == "user" && args[3] == "password" {
			fmt.Println("Possible completions:")
			fmt.Println("  <password>    Password for new user")
			return
		}

		if len(args) >= 5 && args[0] == "create" && args[1] == "user" && args[3] == "password" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Create user with password only")
			fmt.Println("  ssh-key       Add SSH public key")
			return
		}

		if len(args) == 1 && args[0] == "traceroute" {
			showTracerouteHelp()
			return
		}

		if len(args) >= 1 && args[0] == "system" {
			if len(args) == 1 {
				fmt.Println("Possible completions:")
				fmt.Println("  install       Install FloofOS to permanent storage")
				return
			}
			if len(args) == 2 && args[1] == "install" {
				fmt.Println("Possible completions:")
				fmt.Println("  <cr>          Install FloofOS to disk")
				return
			}
		}

		if len(args) == 1 && args[0] == "configure" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Enter configuration mode")
			return
		}

		if len(args) == 1 && args[0] == "exit" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Exit current mode")
			return
		}

		if len(args) == 1 && args[0] == "end" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Exit configuration mode")
			return
		}

		if len(args) == 1 && args[0] == "quit" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Exit FloofOS CLI")
			return
		}

		if len(args) == 1 && args[0] == "help" {
			fmt.Println("Possible completions:")
			fmt.Println("  <cr>          Display help")
			return
		}
	}

	if baseCmd == "" {
		var output strings.Builder
		if currentMode == OperationalMode {
			output.WriteString("\n")
			output.WriteString("Available commands:\n")
			output.WriteString("  configure             Enter configuration mode\n")
			output.WriteString("  exit                  Exit to shell (root only)\n")
			output.WriteString("  help                  Display this text\n")
			output.WriteString("  ping                  Ping remote host\n")
			output.WriteString("  show                  Show system information\n")
			output.WriteString("  system install        Install FloofOS to disk\n")
			output.WriteString("  traceroute            Trace route to destination\n")
			output.WriteString("\n")
		} else {
			output.WriteString("\n")
			output.WriteString("Configuration commands:\n")
			output.WriteString("  backup                Backup and restore operations\n")
			output.WriteString("  commit                Commit configuration changes\n")
			output.WriteString("  create                Create system objects\n")
			output.WriteString("  delete                Delete system objects\n")
			output.WriteString("  exit                  Exit configuration mode\n")
			output.WriteString("  ping                  Ping remote host\n")
			output.WriteString("  rollback              Rollback to previous configuration\n")
			output.WriteString("  set                   Set configuration parameters\n")
			output.WriteString("  show                  Show configuration and status\n")
			output.WriteString("  system                System operations\n")
			output.WriteString("  traceroute            Trace route to destination\n")
			vppCmd := exec.Command("vppctl", "?")
			if vppOutput, err := vppCmd.CombinedOutput(); err == nil && len(vppOutput) > 0 {
				vppStr := strings.TrimSpace(string(vppOutput))
				if vppStr != "" {
					output.WriteString(vppStr)
					output.WriteString("\n")
				}
			}
		}
		printWithPager(output.String())
		return
	}

	args := strings.Fields(baseCmd)

	if len(args) > 0 && args[0] == "traceroute" {
		showTracerouteHelp()
		return
	}

	args = append(args, "?")

	vppCmd := exec.Command("vppctl", args...)
	if output, err := vppCmd.CombinedOutput(); err == nil && len(output) > 0 {
		printWithPager(string(output))
		return
	}

	birdArgs := []string{"netns", "exec", "dataplane", "birdc"}
	birdArgs = append(birdArgs, args...)
	birdCmd := exec.Command("ip", birdArgs...)
	if output, err := birdCmd.CombinedOutput(); err == nil && len(output) > 0 {
		cleaned := cleanBIRDOutput(string(output))
		printWithPager(cleaned)
		return
	}

	fmt.Printf("No help available for: %s\n", baseCmd)
}

func handleSystemCommands(line string, l *liner.State) {
	args := strings.Fields(line)
	if len(args) == 0 {
		return
	}

	if len(args) >= 2 && args[0] == "system" && args[1] == "reboot" {
		if currentMode == ConfigurationMode && hasUnsavedChanges {
			fmt.Println("Warning: You have unsaved configuration. Please 'commit' before reboot")
			fmt.Print("Reboot anyway? (Y/N): ")
			response, err := l.Prompt("")
			if err != nil {
				fmt.Println("\nReboot cancelled.")
				return
			}
			response = strings.TrimSpace(strings.ToUpper(response))
			if response != "Y" && response != "YES" {
				fmt.Println("Reboot cancelled.")
				return
			}
		} else {
			fmt.Print("Reboot system now? (Y/N): ")
			response, err := l.Prompt("")
			if err != nil {
				fmt.Println("\nReboot cancelled.")
				return
			}
			response = strings.TrimSpace(strings.ToUpper(response))
			if response != "Y" && response != "YES" {
				fmt.Println("Reboot cancelled.")
				return
			}
		}

		fmt.Println("Rebooting system...")
		auditLogInfo("System reboot initiated")
		cmd := exec.Command("systemctl", "reboot")
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("reboot")
			cmd.Run()
		}
		return
	}

	if len(args) >= 3 && args[0] == "show" && args[1] == "system" && args[2] == "time" {
		cmd := exec.Command("date", "+%Y-%m-%d %H:%M:%S %Z")
		output, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("Current time: %s", string(output))
		}

		cmd = exec.Command("timedatectl", "show", "-p", "Timezone", "--value")
		output, err = cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("Timezone:     %s", string(output))
		}

		cmd = exec.Command("timedatectl", "show", "-p", "NTP", "--value")
		output, _ = cmd.CombinedOutput()
		ntpEnabled := strings.TrimSpace(string(output)) == "yes"

		fmt.Printf("NTP sync:     %s\n", map[bool]string{true: "enabled", false: "disabled"}[ntpEnabled])

		cmd = exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value")
		output, _ = cmd.CombinedOutput()
		ntpSynced := strings.TrimSpace(string(output)) == "yes"

		fmt.Printf("NTP status:   %s\n", map[bool]string{true: "synchronized", false: "not synchronized"}[ntpSynced])

		cmd = exec.Command("chronyc", "sources")
		output, err = cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			fmt.Printf("\nNTP servers:\n%s", string(output))
		}

		fmt.Println()
		return
	}

	if len(args) >= 4 && args[0] == "set" && args[1] == "system" && args[2] == "time-zone" {
		timezone := strings.Join(args[3:], " ")

		fmt.Printf("Setting timezone to: %s\n", timezone)

		zoneFile := "/usr/share/zoneinfo/" + timezone
		if _, err := os.Stat(zoneFile); os.IsNotExist(err) {
			fmt.Printf("Error: Invalid timezone '%s'\n", timezone)
			fmt.Println("Tip: Use format like 'Asia/Jakarta' or 'UTC'")
			return
		}

		cmd := exec.Command("timedatectl", "set-timezone", timezone)
		if _, err := cmd.CombinedOutput(); err != nil {
			os.Remove("/etc/localtime")
			linkCmd := exec.Command("ln", "-sf", zoneFile, "/etc/localtime")
			if linkErr := linkCmd.Run(); linkErr != nil {
				fmt.Printf("Error setting timezone: %v\n", linkErr)
				return
			}
			os.WriteFile("/etc/timezone", []byte(timezone+"\n"), 0644)
		}
		fmt.Printf("Timezone set to %s\n", timezone)
		hasUnsavedChanges = true
		auditLogConfig(fmt.Sprintf("Set timezone to %s", timezone))
		return
	}

	if len(args) >= 5 && args[0] == "set" && args[1] == "system" && args[2] == "ntp" && args[3] == "server" {
		ntpServer := args[4]

		chronyConf := "/etc/chrony/chrony.conf"

		data, err := os.ReadFile(chronyConf)
		if err != nil {
			fmt.Printf("Error reading chrony config: %v\n", err)
			return
		}

		content := string(data)

		if strings.Contains(content, "server "+ntpServer) {
			fmt.Printf("NTP server %s already configured\n", ntpServer)
			return
		}

		newLine := fmt.Sprintf("server %s iburst\n", ntpServer)
		content += newLine

		err = os.WriteFile(chronyConf, []byte(content), 0644)
		if err != nil {
			fmt.Printf("Error writing chrony config: %v\n", err)
			return
		}

		fmt.Println("Restarting chrony service...")
		cmd := exec.Command("sudo", "systemctl", "restart", "chrony")
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Error restarting chrony: %v\n", err)
		} else {
			fmt.Printf("NTP server %s added successfully\n", ntpServer)
			hasUnsavedChanges = true
			auditLogConfig(fmt.Sprintf("Added NTP server %s", ntpServer))
		}

		cmd = exec.Command("sudo", "timedatectl", "set-ntp", "true")
		cmd.Run()

		return
	}

	if len(args) >= 4 && args[0] == "set" && args[1] == "system" && args[2] == "clock" {
		datetime := strings.Join(args[3:], " ")

		fmt.Printf("Setting system clock to: %s\n", datetime)

		cmd := exec.Command("sudo", "timedatectl", "set-ntp", "false")
		cmd.Run()

		cmd = exec.Command("sudo", "timedatectl", "set-time", datetime)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error setting time: %v\n", err)
			if len(output) > 0 {
				fmt.Print(string(output))
			}
			fmt.Println("\nFormat: YYYY-MM-DD HH:MM:SS (e.g., 2025-11-15 14:30:00)")
		} else {
			fmt.Println("System clock set successfully")
			fmt.Println("Note: NTP sync disabled (use 'set system ntp server' to re-enable)")
			hasUnsavedChanges = true
			auditLogConfig(fmt.Sprintf("Set system clock to %s", datetime))
		}
		return
	}

	fmt.Println("Unknown system command")
}

func handleSystemCommandsInstantHelp(line string) {
	args := strings.Fields(line)
	if len(args) == 0 {
		return
	}

	if len(args) >= 3 && args[0] == "show" && args[1] == "system" && args[2] == "time" {
		cmd := exec.Command("date", "+%Y-%m-%d %H:%M:%S %Z")
		output, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("Current time: %s", string(output))
		}

		cmd = exec.Command("timedatectl", "show", "-p", "Timezone", "--value")
		output, err = cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("Timezone:     %s", string(output))
		}

		cmd = exec.Command("timedatectl", "show", "-p", "NTP", "--value")
		output, _ = cmd.CombinedOutput()
		ntpEnabled := strings.TrimSpace(string(output)) == "yes"

		fmt.Printf("NTP sync:     %s\n", map[bool]string{true: "enabled", false: "disabled"}[ntpEnabled])

		cmd = exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value")
		output, _ = cmd.CombinedOutput()
		ntpSynced := strings.TrimSpace(string(output)) == "yes"

		fmt.Printf("NTP status:   %s\n", map[bool]string{true: "synchronized", false: "not synchronized"}[ntpSynced])

		cmd = exec.Command("chronyc", "sources")
		output, err = cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			fmt.Printf("\nNTP servers:\n%s", string(output))
		}

		fmt.Println()
		return
	}

	if len(args) >= 4 && args[0] == "set" && args[1] == "system" && args[2] == "time-zone" {
		timezone := strings.Join(args[3:], " ")

		fmt.Printf("Setting timezone to: %s\n", timezone)

		zoneFile := "/usr/share/zoneinfo/" + timezone
		if _, err := os.Stat(zoneFile); os.IsNotExist(err) {
			fmt.Printf("Error: Invalid timezone '%s'\n", timezone)
			fmt.Println("Tip: Use format like 'Asia/Jakarta' or 'UTC'")
			return
		}

		cmd := exec.Command("timedatectl", "set-timezone", timezone)
		if _, err := cmd.CombinedOutput(); err != nil {
			os.Remove("/etc/localtime")
			linkCmd := exec.Command("ln", "-sf", zoneFile, "/etc/localtime")
			if linkErr := linkCmd.Run(); linkErr != nil {
				fmt.Printf("Error setting timezone: %v\n", linkErr)
				return
			}
			os.WriteFile("/etc/timezone", []byte(timezone+"\n"), 0644)
		}
		fmt.Printf("Timezone set to %s\n", timezone)
		hasUnsavedChanges = true
		auditLogConfig(fmt.Sprintf("Set timezone to %s", timezone))
		return
	}

	if len(args) >= 5 && args[0] == "set" && args[1] == "system" && args[2] == "ntp" && args[3] == "server" {
		ntpServer := args[4]

		chronyConf := "/etc/chrony/chrony.conf"

		data, err := os.ReadFile(chronyConf)
		if err != nil {
			fmt.Printf("Error reading chrony config: %v\n", err)
			return
		}

		content := string(data)

		if strings.Contains(content, "server "+ntpServer) {
			fmt.Printf("NTP server %s already configured\n", ntpServer)
			return
		}

		newLine := fmt.Sprintf("server %s iburst\n", ntpServer)
		content += newLine

		err = os.WriteFile(chronyConf, []byte(content), 0644)
		if err != nil {
			fmt.Printf("Error writing chrony config: %v\n", err)
			return
		}

		fmt.Println("Restarting chrony service...")
		cmd := exec.Command("sudo", "systemctl", "restart", "chrony")
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Error restarting chrony: %v\n", err)
		} else {
			fmt.Printf("NTP server %s added successfully\n", ntpServer)
			hasUnsavedChanges = true
			auditLogConfig(fmt.Sprintf("Added NTP server %s", ntpServer))
		}

		cmd = exec.Command("sudo", "timedatectl", "set-ntp", "true")
		cmd.Run()

		return
	}

	if len(args) >= 4 && args[0] == "set" && args[1] == "system" && args[2] == "clock" {
		datetime := strings.Join(args[3:], " ")

		fmt.Printf("Setting system clock to: %s\n", datetime)

		cmd := exec.Command("sudo", "timedatectl", "set-ntp", "false")
		cmd.Run()

		cmd = exec.Command("sudo", "timedatectl", "set-time", datetime)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error setting time: %v\n", err)
			if len(output) > 0 {
				fmt.Print(string(output))
			}
			fmt.Println("\nFormat: YYYY-MM-DD HH:MM:SS (e.g., 2025-11-15 14:30:00)")
		} else {
			fmt.Println("System clock set successfully")
			fmt.Println("Note: NTP sync disabled (use 'set system ntp server' to re-enable)")
			hasUnsavedChanges = true
			auditLogConfig(fmt.Sprintf("Set system clock to %s", datetime))
		}
		return
	}

	fmt.Println("Unknown system command")
}

func handleDNSCommand(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage: dns name-server <ip-address> [del]")
		return
	}

	if args[1] != "name-server" {
		fmt.Println("Usage: dns name-server <ip-address> [del]")
		return
	}

	ipAddress := args[2]
	isDelete := false

	if len(args) >= 4 && args[3] == "del" {
		isDelete = true
	}

	if isDelete {
		fmt.Printf("Removing DNS nameserver %s...\n", ipAddress)

		vppCmd := exec.Command("vppctl", "dns", "name-server", ipAddress, "del")
		vppOutput, vppErr := vppCmd.CombinedOutput()
		if vppErr != nil {
			fmt.Printf("Error removing DNS from VPP: %v\n", vppErr)
			if len(vppOutput) > 0 {
				fmt.Print(string(vppOutput))
			}
		} else if len(vppOutput) > 0 {
			fmt.Print(string(vppOutput))
		}

		resolvConf := "/etc/resolv.conf"
		data, err := os.ReadFile(resolvConf)
		if err != nil {
			fmt.Printf("Warning: Could not read %s: %v\n", resolvConf, err)
			return
		}

		lines := strings.Split(string(data), "\n")
		var newLines []string
		targetLine := "nameserver " + ipAddress
		removed := false

		for _, line := range lines {
			if strings.TrimSpace(line) == targetLine {
				removed = true
				continue
			}
			newLines = append(newLines, line)
		}

		if removed {
			newContent := strings.Join(newLines, "\n")
			err = os.WriteFile(resolvConf, []byte(newContent), 0644)
			if err != nil {
				fmt.Printf("Warning: Could not update %s: %v\n", resolvConf, err)
			} else {
				auditLogConfig(fmt.Sprintf("Removed DNS nameserver %s", ipAddress))
			}
		} else {
			fmt.Printf("DNS nameserver %s not found in %s\n", ipAddress, resolvConf)
		}

	} else {
		fmt.Printf("Adding DNS nameserver %s...\n", ipAddress)

		vppCmd := exec.Command("vppctl", "dns", "name-server", ipAddress)
		vppOutput, vppErr := vppCmd.CombinedOutput()
		if vppErr != nil {
			fmt.Printf("Error adding DNS to VPP: %v\n", vppErr)
			if len(vppOutput) > 0 {
				fmt.Print(string(vppOutput))
			}
		} else if len(vppOutput) > 0 {
			fmt.Print(string(vppOutput))
		}

		resolvConf := "/etc/resolv.conf"
		data, err := os.ReadFile(resolvConf)
		if err != nil {
			fmt.Printf("Warning: Could not read %s: %v\n", resolvConf, err)
			return
		}

		content := string(data)
		targetLine := "nameserver " + ipAddress

		if strings.Contains(content, targetLine) {
			fmt.Printf("DNS nameserver %s already in %s\n", ipAddress, resolvConf)
			return
		}

		if !strings.HasSuffix(content, "\n") && len(content) > 0 {
			content += "\n"
		}
		content += targetLine + "\n"

		err = os.WriteFile(resolvConf, []byte(content), 0644)
		if err != nil {
			fmt.Printf("Warning: Could not update %s: %v\n", resolvConf, err)
		} else {
			auditLogConfig(fmt.Sprintf("Added DNS nameserver %s", ipAddress))
		}
	}

	hasUnsavedChanges = true
}

func executeVPP(args []string) {
	if len(args) > 0 && (args[0] == "ping" || args[0] == "monitor") {
		cmd := exec.Command("vppctl", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Error executing VPP command: %v\n", err)
		}
		return
	}

	cmd := exec.Command("vppctl", args...)
	output, err := cmd.CombinedOutput()

	if len(output) > 0 {
		printWithPager(string(output))
	}

	if err != nil && len(output) == 0 {
		fmt.Printf("Error executing VPP command: %v\n", err)
	}
}

func executeBIRD(args []string) {
	cmdArgs := []string{"netns", "exec", "dataplane", "birdc"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("ip", cmdArgs...)
	output, err := cmd.CombinedOutput()

	if len(output) > 0 {
		cleaned := cleanBIRDOutput(string(output))
		printWithPager(cleaned)
	}

	if err != nil && len(output) == 0 {
		fmt.Printf("Error executing BIRD command: %v\n", err)
	}
}

func executeFloofOS(line string) {
	args := strings.Fields(line)
	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "commit":
		var commitComment string
		if len(args) >= 3 && args[1] == "comment" {
			commitComment = strings.Trim(args[2], "\"")
		}

		pvCmd := exec.Command("bash", "-c", "pathvector generate")
		pvOutput, pvErr := pvCmd.CombinedOutput()
		if pvErr != nil {
			fmt.Printf("Error: pathvector generate failed: %v\n", pvErr)
			if len(pvOutput) > 0 {
				fmt.Print(string(pvOutput))
			}
			return
		}

		writeCmd := exec.Command("bash", "-c", "/etc/vppcfg/.venv/bin/vppcfg dump -o /etc/vpp/dataplane.yaml")
		writeOutput, writeErr := writeCmd.CombinedOutput()
		if writeErr != nil {
			fmt.Printf("Error: vppcfg dump failed: %v\n", writeErr)
			if len(writeOutput) > 0 {
				fmt.Print(string(writeOutput))
			}
			return
		}

		fmt.Println("Validating configuration...")
		checkCmd := exec.Command("bash", "-c", "/etc/vppcfg/.venv/bin/vppcfg check -c /etc/vpp/dataplane.yaml")
		checkOutput, checkErr := checkCmd.CombinedOutput()
		if checkErr != nil {
			fmt.Printf("Error: Configuration validation failed:\n")
			if len(checkOutput) > 0 {
				fmt.Print(string(checkOutput))
			}
			return
		}

		commitCmd := exec.Command("bash", "-c", "/etc/vppcfg/.venv/bin/vppcfg plan --novpp -c /etc/vpp/dataplane.yaml -o /etc/vpp/config/vppcfg.vpp")
		commitOutput, commitErr := commitCmd.CombinedOutput()
		if commitErr != nil {
			fmt.Printf("Error: vppcfg plan failed:\n")
			if len(commitOutput) > 0 {
				fmt.Print(string(commitOutput))
			}
			return
		}

		createAutoBackup(commitComment)

		hasUnsavedChanges = false

		auditLogCommit("Configuration committed successfully")
		fmt.Println("Configuration committed successfully")

	case "backup":
		if len(args) < 2 {
			fmt.Println("Usage: backup <export|import> <name> [path <path>]")
			return
		}

		subCmd := args[1]
		switch subCmd {
		case "export":
			if len(args) < 3 {
				fmt.Println("Usage: backup export <name> [path <path>]")
				return
			}
			name := args[2]
			exportPath := backupDir
			if len(args) >= 5 && args[3] == "path" {
				exportPath = args[4]
			}
			backupExport(name, exportPath)

		case "import":
			if len(args) < 3 {
				fmt.Println("Usage: backup import <name> [path <path>]")
				fmt.Println("Type 'show backups' for available backups")
				return
			}
			name := args[2]
			importPath := ""
			if len(args) >= 5 && args[3] == "path" {
				importPath = args[4]
			}
			backupImport(name, importPath)

		default:
			fmt.Println("Unknown backup command. Use: export, import")
		}

	case "rollback":
		if len(args) == 1 {
			restoreRollback(0)
			return
		}

		if args[1] == "?" {
			showRollbackHelp()
			return
		}

		var rollbackNum int
		_, err := fmt.Sscanf(args[1], "%d", &rollbackNum)
		if err != nil || rollbackNum < 0 || rollbackNum > 49 {
			fmt.Println("Error: Invalid rollback number (use 0-49)")
			fmt.Println("Type 'rollback ?' for help")
			return
		}

		restoreRollback(rollbackNum)

	case "set":
		if len(args) < 2 {
			fmt.Println("Usage: set <parameter> <value>")
			return
		}
		if args[1] == "hostname" && len(args) >= 3 {
			setHostname(args[2])
			hasUnsavedChanges = true
		} else if args[1] == "all" {
			if len(args) >= 3 && args[2] == "logging" {
				if len(args) < 4 {
					fmt.Println("Usage: set all logging <enable|disable>")
					return
				}
				if args[3] == "enable" {
					setLogGlobalEnable()
				} else if args[3] == "disable" {
					if len(args) >= 5 && args[4] == "confirm" {
						setLogGlobalDisableConfirmed()
					} else {
						setLogGlobalDisable()
					}
				} else {
					fmt.Println("Usage: set all logging <enable|disable>")
				}
			} else {
				fmt.Println("Unknown parameter")
			}
		} else if args[1] == "protocol" {
			if len(args) >= 3 && args[2] == "bgp" {
				if len(args) >= 4 && args[3] == "logging" {
					if len(args) < 5 {
						fmt.Println("Usage: set protocol bgp logging <enable|disable>")
						return
					}
					if args[4] == "enable" {
						setLogBGPEnable()
					} else if args[4] == "disable" {
						setLogBGPDisable()
					} else {
						fmt.Println("Usage: set protocol bgp logging <enable|disable>")
					}
				} else if len(args) == 3 {
					editBGPConfig()
					hasUnsavedChanges = true
				}
			} else {
				fmt.Println("Unknown protocol")
			}
		} else if args[1] == "bgp" {
			if len(args) >= 3 && args[2] == "logging" {
				if len(args) < 4 {
					fmt.Println("Usage: set protocol bgp logging <enable|disable>")
					return
				}
				if args[3] == "enable" {
					setLogBGPEnable()
				} else if args[3] == "disable" {
					setLogBGPDisable()
				} else {
					fmt.Println("Usage: set bgp logging <enable|disable>")
				}
			} else {
				editBGPConfig()
				hasUnsavedChanges = true
			}
		} else if args[1] == "system" {
			if len(args) >= 3 && args[2] == "logging" {
				if len(args) < 4 {
					fmt.Println("Usage: set system logging <enable|disable>")
					return
				}
				if args[3] == "enable" {
					setLogSystemEnable()
				} else if args[3] == "disable" {
					setLogSystemDisable()
				} else {
					fmt.Println("Usage: set system logging <enable|disable>")
				}
			} else {
				fmt.Println("Unknown parameter")
			}
		} else if args[1] == "security" {
			handleSecuritySetCommands(args[2:])
		} else if args[1] == "snmp" {
			handleSNMPSetCommands(args[2:])
		} else {
			fmt.Println("Unknown set parameter. Available: hostname, all, bgp, system, security, snmp")
		}

	case "create":
		if len(args) >= 2 && args[1] == "user" {
			if len(args) < 4 || args[2] == "" {
				fmt.Println("Usage: create user <username> password <password> [ssh-key <public-key>]")
				return
			}
			if args[3] != "password" || len(args) < 5 {
				fmt.Println("Usage: create user <username> password <password> [ssh-key <public-key>]")
				return
			}

			username := args[2]
			password := args[4]

			var sshKey string
			if len(args) >= 7 && args[5] == "ssh-key" {
				sshKey = strings.Join(args[6:], " ")
			}

			createSimpleUserWithKey(username, password, sshKey)
		} else {
			fmt.Println("Usage: create user <username> password <password> [ssh-key <public-key>]")
		}

	case "show":
		if len(args) >= 2 && args[1] == "configuration" {
			showConfiguration()
		} else if len(args) >= 2 && (args[1] == "backups" || args[1] == "backup") {
			showAllBackups()
		} else if len(args) >= 3 && args[1] == "system" && args[2] == "logging" {
			showSystemLog(args[3:])
		} else if len(args) >= 3 && args[1] == "system" && args[2] == "commit" {
			showCommitHistory()
		} else if len(args) >= 3 && args[1] == "system" && args[2] == "time" {
			showSystemTime()
		} else if len(args) >= 2 && args[1] == "system" {
			showSystem()
		} else if len(args) >= 2 && args[1] == "resource" {
			showResource()
		} else if len(args) >= 2 && args[1] == "users" {
			showUsers()
		} else if len(args) >= 4 && args[1] == "protocol" && args[2] == "bgp" && args[3] == "logging" {
			showBGPLog(args[4:])
		} else if len(args) >= 3 && args[1] == "protocol" && args[2] == "bgp" {
			executePathvector(args[2:])
		} else if len(args) >= 4 && args[1] == "traffic" && args[2] == "interface" {
			showTrafficInterface(args[3])
		} else if len(args) >= 2 && args[1] == "security" {
			handleSecurityShowCommands(args[2:])
		} else if len(args) >= 2 && args[1] == "snmp" {
			handleSNMPShowCommands(args[2:])
		} else if len(args) == 1 {
			showConfiguration()
		} else {
			fmt.Println("Unknown show command")
		}

	case "delete":
		if len(args) >= 2 && args[1] == "user" {
			if len(args) < 3 {
				fmt.Println("Usage: delete user <username>")
				return
			}
			deleteSystemUser(args[2])
		} else if len(args) >= 2 && args[1] == "security" {
			handleSecurityDeleteCommands(args[2:])
		} else {
			fmt.Println("Usage: delete user <username> | delete security ...")
		}

	default:
		fmt.Println("Unknown FloofOS command")
	}
}

func createSimpleUser(username, password string) {
	createSimpleUserWithKey(username, password, "")
}

func createSimpleUserWithKey(username, password, sshKey string) {
	if username == "" {
		fmt.Println("Error: Invalid username (cannot be empty)")
		return
	}

	if len(password) < 4 {
		fmt.Println("Error: Password must be at least 4 characters")
		return
	}

	if username == "root" {
		createSystemUser(username, password, PrivilegeAdmin)

		if sshKey != "" {
			if err := security.AddSSHKey(username, sshKey); err != nil {
				fmt.Printf("Warning: Failed to add SSH key: %v\n", err)
			} else {
				fmt.Println("SSH public key added for root")
				auditLogInfo("Added SSH key for root")
			}
		}
		return
	}

	createSystemUser(username, password, PrivilegeAdmin)

	if sshKey != "" {
		if err := security.AddSSHKey(username, sshKey); err != nil {
			fmt.Printf("Warning: Failed to add SSH key: %v\n", err)
			fmt.Println("User created successfully, but SSH key setup failed")
		} else {
			fmt.Printf("SSH public key added for user '%s'\n", username)
			auditLogInfo(fmt.Sprintf("Added SSH key for user: %s", username))
		}
	}
}

func handleSystemLoginCommand(args []string) {

	if len(args) < 5 {
		fmt.Println("Usage: set system login user <username> authentication plain-text-password <password> class <admin|operator|viewer>")
		return
	}

	username := args[0]

	if args[1] != "authentication" || args[2] != "plain-text-password" {
		fmt.Println("Usage: set system login user <username> authentication plain-text-password <password> class <admin|operator|viewer>")
		return
	}

	password := args[3]

	if args[4] != "class" || len(args) < 6 {
		fmt.Println("Usage: set system login user <username> authentication plain-text-password <password> class <admin|operator|viewer>")
		return
	}

	className := args[5]

	if username == "" {
		fmt.Println("Error: Invalid username (cannot be empty)")
		return
	}

	if len(password) < 4 {
		fmt.Println("Error: Password must be at least 4 characters")
		return
	}

	privilege, err := stringToPrivilege(className)
	if err != nil {
		fmt.Println(err)
		return
	}

	createSystemUser(username, password, privilege)
}

func createSystemUser(username, password string, privilege UserPrivilege) {
	if username == "root" {
		fmt.Println("Updating root password...")
		chpasswdCmd := exec.Command("bash", "-c", fmt.Sprintf("echo 'root:%s' | chpasswd", password))
		if err := chpasswdCmd.Run(); err != nil {
			fmt.Printf("Error: Failed to update root password: %v\n", err)
			return
		}
		auditLogConfig("Updated root password")
		fmt.Println("Root password updated successfully")
		return
	}

	fmt.Printf("Creating user '%s' with %s privilege...\n", username, privilegeToString(privilege))

	checkCmd := exec.Command("id", username)
	userExists := (checkCmd.Run() == nil)

	if userExists {
		fmt.Printf("Linux user '%s' already exists, updating...\n", username)

		chpasswdCmd := exec.Command("bash", "-c", fmt.Sprintf("echo '%s:%s' | chpasswd", username, password))
		if err := chpasswdCmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to update password: %v\n", err)
		}
	} else {
		useraddCmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
		if err := useraddCmd.Run(); err != nil {
			fmt.Printf("Error: Failed to create Linux user: %v\n", err)
			return
		}

		chpasswdCmd := exec.Command("bash", "-c", fmt.Sprintf("echo '%s:%s' | chpasswd", username, password))
		if err := chpasswdCmd.Run(); err != nil {
			fmt.Printf("Error: Failed to set password: %v\n", err)
			return
		}
	}

	bashrcContent := `
# FloofCTL Auto-launch
if [[ -t 0 && -z "$FLOOFCTL_SHELL" ]]; then
    export FLOOFCTL_SHELL=1
    exec /usr/local/bin/cli
fi
`
	homeDir := fmt.Sprintf("/home/%s", username)
	bashrcPath := fmt.Sprintf("%s/.bashrc", homeDir)

	existingContent := ""
	if data, err := os.ReadFile(bashrcPath); err == nil {
		existingContent = string(data)
	}

	lines := strings.Split(existingContent, "\n")
	var newLines []string
	skipFloofCTL := false
	for _, line := range lines {
		if strings.Contains(line, "# FloofCTL Auto-launch") {
			skipFloofCTL = true
			continue
		}
		if skipFloofCTL {
			if strings.TrimSpace(line) == "fi" {
				skipFloofCTL = false
			}
			continue
		}
		newLines = append(newLines, line)
	}

	newContent := strings.Join(newLines, "\n")
	newContent = strings.TrimSpace(newContent) + "\n" + bashrcContent

	if err := os.WriteFile(bashrcPath, []byte(newContent), 0644); err != nil {
		fmt.Printf("Warning: Failed to update .bashrc: %v\n", err)
	} else {
		exec.Command("chown", fmt.Sprintf("%s:%s", username, username), bashrcPath).Run()
	}

	sudoersContent := fmt.Sprintf("# FloofCTL sudoers for %s\n", username)
	sudoersContent += fmt.Sprintf("%s ALL=(ALL) NOPASSWD:SETENV: /usr/local/bin/cli\n", username)
	sudoersContent += fmt.Sprintf("%s ALL=(ALL) NOPASSWD: /sbin/ip netns exec dataplane /usr/bin/floof-cli\n", username)
	sudoersContent += fmt.Sprintf("%s ALL=(ALL) NOPASSWD: /usr/bin/vppctl *\n", username)
	sudoersContent += fmt.Sprintf("%s ALL=(ALL) NOPASSWD: /usr/sbin/birdc *\n", username)
	sudoersContent += fmt.Sprintf("%s ALL=(ALL) NOPASSWD: /etc/vppcfg/.venv/bin/vppcfg *\n", username)

	sudoersFile := fmt.Sprintf("/etc/sudoers.d/cli-%s", username)
	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0440); err != nil {
		fmt.Printf("Warning: Failed to create sudoers file: %v\n", err)
	}

	db, err := loadUsers()
	if err != nil {
		fmt.Printf("Error: Failed to load user database: %v\n", err)
		return
	}

	found := false
	for i, u := range db.Users {
		if u.Username == username {
			db.Users[i].Privilege = privilege
			found = true
			break
		}
	}

	if !found {
		newUser := User{
			Username:  username,
			Privilege: privilege,
			Created:   time.Now().Format("2006-01-02 15:04:05"),
		}
		db.Users = append(db.Users, newUser)
	}

	if err := saveUsers(db); err != nil {
		fmt.Printf("Error: Failed to save user database: %v\n", err)
		return
	}

	auditLogConfig(fmt.Sprintf("Created user '%s'", username))
	fmt.Printf("User '%s' created successfully\n", username)
	fmt.Println("User will automatically enter CLI on next login")
}

func deleteSystemUser(username string) {

	if username == "root" {
		fmt.Println("Error: Cannot delete root user")
		return
	}

	if currentUser != nil && username == currentUser.Username {
		fmt.Println("Error: Cannot delete currently logged-in user")
		return
	}

	fmt.Printf("Deleting user '%s'...\n", username)

	db, err := loadUsers()
	if err != nil {
		fmt.Printf("Error: Failed to load user database: %v\n", err)
		return
	}

	found := false
	newUsers := []User{}
	for _, u := range db.Users {
		if u.Username == username {
			found = true
			continue
		}
		newUsers = append(newUsers, u)
	}

	if !found {
		fmt.Printf("Warning: User '%s' not found in database\n", username)
	} else {
		db.Users = newUsers
		if err := saveUsers(db); err != nil {
			fmt.Printf("Error: Failed to save user database: %v\n", err)
			return
		}
	}

	sudoersFile := fmt.Sprintf("/etc/sudoers.d/cli-%s", username)
	os.Remove(sudoersFile)

	userdelCmd := exec.Command("userdel", "-r", username)
	if err := userdelCmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to delete Linux user (may not exist): %v\n", err)
	}

	auditLogConfig(fmt.Sprintf("Deleted user '%s'", username))
	fmt.Printf("User '%s' deleted successfully\n", username)
}

func showUsers() {
	db, err := loadUsers()
	if err != nil {
		fmt.Printf("Error: Failed to load user database: %v\n", err)
		return
	}

	fmt.Println("FloofCTL Users:")
	fmt.Println()

	fmt.Printf("  %-20s %-12s %s\n", "root", "admin", "(system)")

	if len(db.Users) == 0 {
		fmt.Println("  (no additional users)")
	} else {
		for _, user := range db.Users {
			fmt.Printf("  %-20s %-12s %s\n", user.Username, privilegeToString(user.Privilege), user.Created)
		}
	}

	fmt.Println()

	if currentUser != nil {
		fmt.Printf("Current user: %s (%s)\n", currentUser.Username, privilegeToString(currentUser.Privilege))
	}
}

func showSystemLog(args []string) {
	if !isLoggingSystemEnabled() {
		fmt.Println("Audit logging is disabled")
		return
	}

	if _, err := os.Stat(auditLog); os.IsNotExist(err) {
		fmt.Println("No audit logs found")
		return
	}

	lines := 50
	filter := ""
	filterType := ""

	if len(args) > 0 {
		switch args[0] {
		case "last":
			if len(args) >= 2 {
				n, err := strconv.Atoi(args[1])
				if err == nil && n > 0 {
					lines = n
				}
			}
		case "user":
			if len(args) >= 2 {
				filter = args[1]
				filterType = "user"
			}
		case "config":
			filter = "[CONFIG]"
			filterType = "level"
		case "commit":
			filter = "[COMMIT]"
			filterType = "level"
		case "today":
			filter = time.Now().Format("2006-01-02")
			filterType = "date"
		}
	}

	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), auditLog)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return
	}

	logLines := strings.Split(string(output), "\n")

	fmt.Println("Audit Log:")
	fmt.Println()

	count := 0
	for _, line := range logLines {
		if line == "" {
			continue
		}

		if filterType != "" {
			if filterType == "user" && !strings.Contains(line, fmt.Sprintf("%s:", filter)) {
				continue
			}
			if filterType == "level" && !strings.Contains(line, filter) {
				continue
			}
			if filterType == "date" && !strings.HasPrefix(line, filter) {
				continue
			}
		}

		fmt.Println(line)
		count++
	}

	if count == 0 {
		fmt.Println("(no matching log entries)")
	}
	fmt.Println()
}

func showBGPLog(args []string) {
	if !isLoggingBGPEnabled() {
		fmt.Println("BGP logging is disabled")
		fmt.Println("Use 'set log bgp enable' to view BGP logs")
		return
	}

	syslogPath := "/var/log/syslog"

	if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
		fmt.Println("No BGP logs found")
		return
	}

	lines := 100
	matchPattern := ""
	pipeMode := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "last":
			if i+1 < len(args) {
				n, err := strconv.Atoi(args[i+1])
				if err == nil && n > 0 {
					lines = n
				}
				i++
			}
		case "|":
			pipeMode = true
		case "match":
			if pipeMode && i+1 < len(args) {
				matchPattern = args[i+1]
				i++
			}
		}
	}

	cmdArgs := []string{"-n", strconv.Itoa(lines), syslogPath}
	tailCmd := exec.Command("tail", cmdArgs...)

	grepCmd := exec.Command("grep", "bird")

	var finalCmd *exec.Cmd
	if matchPattern != "" {
		matchCmd := exec.Command("grep", matchPattern)

		pipe1, _ := tailCmd.StdoutPipe()
		pipe2, _ := grepCmd.StdoutPipe()

		grepCmd.Stdin = pipe1
		matchCmd.Stdin = pipe2
		finalCmd = matchCmd
	} else {
		pipe, _ := tailCmd.StdoutPipe()
		grepCmd.Stdin = pipe
		finalCmd = grepCmd
	}

	tailCmd.Start()
	grepCmd.Start()
	if matchPattern != "" {
		finalCmd.Start()
	}

	output, err := finalCmd.Output()
	if err != nil {
		if len(output) == 0 {
			fmt.Println("No BGP log entries found")
			return
		}
	}

	fmt.Println("BGP Log (last", lines, "syslog entries):")
	fmt.Println()
	fmt.Print(string(output))
	fmt.Println()
}

func showConfiguration() {
	var output strings.Builder

	floofVersion := "1.0"
	osReleaseData, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(osReleaseData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VERSION=") {
				floofVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
				break
			}
		}
	}

	lastCommitTime := "never"
	lastCommitUser := "unknown"
	rollback0 := "/etc/floofos-config/commits/0"
	if info, err := os.Stat(rollback0); err == nil {
		lastCommitTime = info.ModTime().Format("2006-01-02 15:04:05-07:00")
		if logData, err := os.ReadFile("/var/log/floofos-audit.log"); err == nil {
			logLines := strings.Split(string(logData), "\n")
			for i := len(logLines) - 1; i >= 0; i-- {
				if strings.Contains(logLines[i], "[COMMIT]") {
					parts := strings.Split(logLines[i], " ")
					for _, p := range parts {
						if strings.HasPrefix(p, "user=") {
							lastCommitUser = strings.TrimPrefix(p, "user=")
							break
						}
					}
					break
				}
			}
		}
		if lastCommitUser == "unknown" {
			if currentUser, err := user.Current(); err == nil {
				lastCommitUser = currentUser.Username
			}
		}
	}

	output.WriteString(fmt.Sprintf("!Version FloofOS %s\n", floofVersion))
	output.WriteString(fmt.Sprintf("!Last configuration was updated at %s by %s\n", lastCommitTime, lastCommitUser))
	output.WriteString("!\n")

	if hostname, err := os.ReadFile("/etc/hostname"); err == nil {
		h := strings.TrimSpace(string(hostname))
		if h != "" {
			output.WriteString(fmt.Sprintf("set hostname %s\n", h))
			output.WriteString("!\n")
		}
	}

	systemLines := []string{}
	if tz, err := os.ReadFile("/etc/timezone"); err == nil {
		t := strings.TrimSpace(string(tz))
		if t != "" {
			systemLines = append(systemLines, fmt.Sprintf("set system time-zone %s", t))
		}
	}
	systemEnabled := true
	if logData, err := os.ReadFile("/etc/floofctl/log.conf"); err == nil {
		lines := strings.Split(string(logData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOGGING_SYSTEM_ENABLED=") {
				systemEnabled = strings.TrimPrefix(line, "LOGGING_SYSTEM_ENABLED=") == "true"
			}
		}
	}
	if systemEnabled {
		systemLines = append(systemLines, "set system logging enable")
	} else {
		systemLines = append(systemLines, "set system logging disable")
	}
	if len(systemLines) > 0 {
		for _, l := range systemLines {
			output.WriteString(l + "\n")
		}
		output.WriteString("!\n")
	}

	globalEnabled := true
	if logData, err := os.ReadFile("/etc/floofctl/log.conf"); err == nil {
		lines := strings.Split(string(logData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOGGING_GLOBAL_ENABLED=") {
				globalEnabled = strings.TrimPrefix(line, "LOGGING_GLOBAL_ENABLED=") == "true"
			}
		}
	}
	if globalEnabled {
		output.WriteString("set all logging enable\n")
	} else {
		output.WriteString("set all logging disable\n")
	}
	output.WriteString("!\n")

	if passwdData, err := os.ReadFile("/etc/passwd"); err == nil {
		lines := strings.Split(string(passwdData), "\n")
		userLines := []string{}
		for _, line := range lines {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) < 7 {
				continue
			}
			username := parts[0]
			uidStr := parts[2]
			shell := parts[6]

			uidNum, err := strconv.Atoi(uidStr)
			if err != nil || uidNum < 1000 {
				continue
			}
			if username == "nobody" || username == "nogroup" || username == "nfsnobody" {
				continue
			}
			if shell == "/usr/sbin/nologin" || shell == "/bin/false" || shell == "/sbin/nologin" {
				continue
			}

			homeDir := parts[5]
			sshKeyFile := homeDir + "/.ssh/authorized_keys"
			hasSSHKey := false
			if _, err := os.Stat(sshKeyFile); err == nil {
				hasSSHKey = true
			}

			if hasSSHKey {
				userLines = append(userLines, fmt.Sprintf("create user %s password **** ssh-key ****", username))
			} else {
				userLines = append(userLines, fmt.Sprintf("create user %s password ****", username))
			}
		}
		if len(userLines) > 0 {
			for _, l := range userLines {
				output.WriteString(l + "\n")
			}
			output.WriteString("!\n")
		}
	}

	vppCommands := getVPPConfigGroupedClean()
	if len(vppCommands) > 0 {
		for _, group := range vppCommands {
			for _, cmd := range group {
				output.WriteString(cmd + "\n")
			}
			output.WriteString("!\n")
		}
	}

	bgpEnabled := true
	if logData, err := os.ReadFile("/etc/floofctl/log.conf"); err == nil {
		lines := strings.Split(string(logData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOGGING_BGP_ENABLED=") {
				bgpEnabled = strings.TrimPrefix(line, "LOGGING_BGP_ENABLED=") == "true"
			}
		}
	}
	if info, err := os.Stat("/etc/pathvector.yml"); err == nil {
		lastMod := info.ModTime().Format("2006-01-02 15:04:05")
		output.WriteString(fmt.Sprintf("!BGP Configuration Last modified: %s\n", lastMod))
		output.WriteString("!Edit with: set protocol bgp\n")
		if bgpEnabled {
			output.WriteString("set protocol bgp logging enable\n")
		} else {
			output.WriteString("set protocol bgp logging disable\n")
		}
		output.WriteString("!\n")
	}

	securityLines := []string{}
	firewallEnabled := false
	cmd := exec.Command("systemctl", "is-active", "nftables-dataplane.service")
	if cmdOutput, err := cmd.CombinedOutput(); err == nil && strings.TrimSpace(string(cmdOutput)) == "active" {
		firewallEnabled = true
	}

	if firewallEnabled {
		securityLines = append(securityLines, "set security firewall enable")
		nftCmd := exec.Command("nft", "list", "table", "inet", "floofos")
		if nftOutput, err := nftCmd.CombinedOutput(); err == nil {
			rules := parseFirewallRulesForConfig(string(nftOutput))
			securityLines = append(securityLines, rules...)
		}
	} else {
		securityLines = append(securityLines, "set security firewall disable")
	}

	fail2banCmd := exec.Command("systemctl", "is-active", "fail2ban")
	if fail2banOutput, err := fail2banCmd.CombinedOutput(); err == nil && strings.TrimSpace(string(fail2banOutput)) == "active" {
		securityLines = append(securityLines, "set security fail2ban enable")
	} else {
		securityLines = append(securityLines, "set security fail2ban disable")
	}

	sshdConfig, err := os.ReadFile("/etc/ssh/sshd_config")
	if err == nil {
		lines := strings.Split(string(sshdConfig), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "PasswordAuthentication") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					if strings.ToLower(parts[1]) == "yes" {
						securityLines = append(securityLines, "set security ssh-password-auth enable")
					} else {
						securityLines = append(securityLines, "set security ssh-password-auth disable")
					}
				}
				break
			}
		}
	}

	if len(securityLines) > 0 {
		for _, l := range securityLines {
			output.WriteString(l + "\n")
		}
		output.WriteString("!\n")
	}

	snmpdActive := false
	cmd = exec.Command("systemctl", "is-active", "snmpd-dataplane.service")
	if cmdOutput, err := cmd.CombinedOutput(); err == nil && strings.TrimSpace(string(cmdOutput)) == "active" {
		snmpdActive = true
	}

	if snmpdActive {
		snmpLines := []string{"set snmp enable"}
		if snmpData, err := os.ReadFile("/etc/snmp/snmpd-dataplane.conf"); err == nil {
			lines := strings.Split(string(snmpData), "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || trimmed == "" {
					continue
				}
				if strings.HasPrefix(trimmed, "rocommunity ") {
					parts := strings.Fields(trimmed)
					if len(parts) >= 2 {
						snmpLines = append(snmpLines, fmt.Sprintf("set snmp community %s", parts[1]))
					}
				}
				if strings.HasPrefix(trimmed, "syslocation ") {
					loc := strings.TrimPrefix(trimmed, "syslocation ")
					snmpLines = append(snmpLines, fmt.Sprintf("set snmp location %s", loc))
				}
				if strings.HasPrefix(trimmed, "syscontact ") {
					contact := strings.TrimPrefix(trimmed, "syscontact ")
					snmpLines = append(snmpLines, fmt.Sprintf("set snmp contact %s", contact))
				}
			}
		}
		for _, l := range snmpLines {
			output.WriteString(l + "\n")
		}
		output.WriteString("!\n")
	}

	output.WriteString("end\n")
	printWithPager(output.String())
}

func getVPPConfigGrouped() [][]string {
	var allCommands []string

	for _, file := range []string{"/etc/vpp/config/head.vpp", "/etc/vpp/config/vppcfg.vpp", "/etc/vpp/config/tail.vpp"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			allCommands = append(allCommands, trimmed)
		}
	}

	if len(allCommands) == 0 {
		return nil
	}

	groups := make(map[string][]string)
	groupOrder := []string{}

	for _, cmd := range allCommands {
		parts := strings.Fields(cmd)
		var prefix string
		if len(parts) >= 2 {
			prefix = parts[0] + " " + parts[1]
			if prefix == "set interface" && len(parts) >= 3 {
				thirdWord := parts[2]
				if thirdWord == "state" || thirdWord == "ip" || thirdWord == "mtu" || thirdWord == "rx-mode" {
					prefix = prefix + " " + thirdWord
				}
			}
		} else if len(parts) == 1 {
			prefix = parts[0]
		} else {
			continue
		}

		if _, exists := groups[prefix]; !exists {
			groupOrder = append(groupOrder, prefix)
		}
		groups[prefix] = append(groups[prefix], cmd)
	}

	var result [][]string
	for _, prefix := range groupOrder {
		result = append(result, groups[prefix])
	}

	return result
}

func getVPPConfigGroupedClean() [][]string {
	var allCommands []string

	for _, file := range []string{"/etc/vpp/config/head.vpp", "/etc/vpp/config/vppcfg.vpp", "/etc/vpp/config/tail.vpp"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.HasPrefix(trimmed, "comment {") {
				continue
			}
			allCommands = append(allCommands, trimmed)
		}
	}

	if len(allCommands) == 0 {
		return nil
	}

	groups := make(map[string][]string)
	groupOrder := []string{}

	for _, cmd := range allCommands {
		parts := strings.Fields(cmd)
		var prefix string
		if len(parts) >= 2 {
			prefix = parts[0] + " " + parts[1]
			if prefix == "set interface" && len(parts) >= 3 {
				thirdWord := parts[2]
				if thirdWord == "state" || thirdWord == "ip" || thirdWord == "mtu" || thirdWord == "rx-mode" {
					prefix = prefix + " " + thirdWord
				}
			}
			if prefix == "lcp create" {
				prefix = "lcp create"
			}
		} else if len(parts) == 1 {
			prefix = parts[0]
		} else {
			continue
		}

		if _, exists := groups[prefix]; !exists {
			groupOrder = append(groupOrder, prefix)
		}
		groups[prefix] = append(groups[prefix], cmd)
	}

	var result [][]string
	for _, prefix := range groupOrder {
		result = append(result, groups[prefix])
	}

	return result
}

func parseFirewallRulesForConfig(rulesetStr string) []string {
	var rules []string

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

		if strings.Contains(line, `comment "system-`) {
			continue
		}

		commentRegex := regexp.MustCompile(`comment "([^"]+)"`)
		matches := commentRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		ruleName := matches[1]

		protocol := ""
		if strings.Contains(line, "tcp dport") {
			protocol = "tcp"
		} else if strings.Contains(line, "udp dport") {
			protocol = "udp"
		}

		port := ""
		portRegex := regexp.MustCompile(`(tcp|udp) dport (\d+)`)
		if portMatches := portRegex.FindStringSubmatch(line); len(portMatches) > 2 {
			port = portMatches[2]
		}

		srcAddress := ""
		srcRegex := regexp.MustCompile(`ip saddr ([0-9./]+)`)
		if srcMatches := srcRegex.FindStringSubmatch(line); len(srcMatches) > 1 {
			srcAddress = srcMatches[1]
		}

		action := "accept"
		if strings.Contains(line, "drop") {
			action = "drop"
		}

		if protocol != "" && port != "" {
			configLine := fmt.Sprintf("set security firewall rule %s protocol %s port %s", ruleName, protocol, port)
			if srcAddress != "" && srcAddress != "0.0.0.0/0" {
				configLine += fmt.Sprintf(" src-address %s", srcAddress)
			}
			configLine += fmt.Sprintf(" action %s", action)
			rules = append(rules, configLine)
		}
	}

	return rules
}

func editBGPConfig() {
	editor := "micro"

	cmd := exec.Command(editor, "/etc/pathvector.yml")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error opening editor: %v\n", err)
		return
	}

	fmt.Println("BGP configuration updated. Run 'commit' to apply changes.")
}

func isBIRDCommand(line string) bool {
	birdCmds := []string{"protocols", "symbols", "route", "filter", "enable", "disable", "restart", "reload"}

	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	firstWord := args[0]
	for _, cmd := range birdCmds {
		if firstWord == cmd {
			return true
		}
	}

	if firstWord == "show" && len(args) > 1 {
		secondWord := args[1]
		for _, cmd := range birdCmds {
			if secondWord == cmd {
				return true
			}
		}
	}

	return false
}

func isFloofOSCommand(line string) bool {
	args := strings.Fields(line)
	if len(args) == 0 {
		return false
	}

	firstWord := args[0]

	if firstWord == "commit" || firstWord == "backup" || firstWord == "rollback" {
		return true
	}

	if firstWord == "create" && len(args) >= 2 && args[1] == "user" {
		return true
	}
	if firstWord == "delete" && len(args) >= 2 {
		if args[1] == "user" || args[1] == "security" {
			return true
		}
	}

	if firstWord == "set" && len(args) >= 2 {
		secondWord := args[1]
		if secondWord == "protocol" || secondWord == "bgp" || secondWord == "hostname" ||
			secondWord == "security" || secondWord == "snmp" ||
			secondWord == "all" {
			return true
		}
		return false
	}

	if firstWord == "show" {
		if len(args) == 1 {
			return true
		}
		secondWord := args[1]
		if secondWord == "configuration" || secondWord == "backups" || secondWord == "backup" ||
			secondWord == "system" || secondWord == "resource" || secondWord == "users" || secondWord == "log" ||
			secondWord == "security" || secondWord == "snmp" {
			return true
		}
		if secondWord == "traffic" && len(args) >= 4 && args[2] == "interface" {
			return true
		}
	}

	return false
}

func executePathvector(args []string) {

	if len(args) == 1 && args[0] == "bgp" {
		cmd := exec.Command("pathvector", "status")
		output, err := cmd.CombinedOutput()

		if len(output) > 0 {
			fmt.Print(string(output))
		}

		if err != nil && len(output) == 0 {
			fmt.Printf("Error: pathvector command failed: %v\n", err)
			fmt.Println("Make sure pathvector is installed and configured")
		}
		return
	}

	if len(args) >= 2 && args[0] == "bgp" && args[1] == "summary" {
		cmd := exec.Command("ip", "netns", "exec", "dataplane", "birdc", "show", "protocols", "all")
		output, err := cmd.CombinedOutput()

		if len(output) > 0 {
			cleaned := cleanBIRDOutput(string(output))
			printWithPager(cleaned)
		}

		if err != nil && len(output) == 0 {
			fmt.Printf("Error: BIRD command failed: %v\n", err)
			fmt.Println("Make sure BIRD is running in dataplane namespace")
		}
		return
	}

	cmd := exec.Command("pathvector", args...)
	output, err := cmd.CombinedOutput()

	if len(output) > 0 {
		fmt.Print(string(output))
	}

	if err != nil && len(output) == 0 {
		fmt.Printf("Error: pathvector command failed: %v\n", err)
	}
}

func showSystem() {
	fmt.Println()
	fmt.Println("FloofOS System Information")
	fmt.Println()

	floofVersion := "Unknown"
	osReleaseData, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(osReleaseData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VERSION=") {
				floofVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
				break
			} else if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				if strings.Contains(name, "FloofOS") {
					floofVersion = name
				}
			}
		}
	}
	if floofVersion == "Unknown" {
		lsbCmd := exec.Command("lsb_release", "-d", "-s")
		if lsbOutput, err := lsbCmd.Output(); err == nil {
			floofVersion = strings.TrimSpace(string(lsbOutput))
		}
	}

	hostname, _ := os.Hostname()

	uptimeData, _ := os.ReadFile("/proc/uptime")
	uptimeStr := "Unknown"
	if len(uptimeData) > 0 {
		parts := strings.Fields(string(uptimeData))
		if len(parts) > 0 {
			uptimeSec, _ := strconv.ParseFloat(parts[0], 64)
			days := int(uptimeSec / 86400)
			hours := int((uptimeSec - float64(days*86400)) / 3600)
			minutes := int((uptimeSec - float64(days*86400) - float64(hours*3600)) / 60)
			uptimeStr = fmt.Sprintf("%d days, %d hours, %d minutes", days, hours, minutes)
		}
	}

	kernelCmd := exec.Command("uname", "-r")
	kernelOutput, _ := kernelCmd.Output()
	kernelVersion := strings.TrimSpace(string(kernelOutput))

	loadData, _ := os.ReadFile("/proc/loadavg")
	loadAvg := "Unknown"
	if len(loadData) > 0 {
		parts := strings.Fields(string(loadData))
		if len(parts) >= 3 {
			loadAvg = fmt.Sprintf("%s, %s, %s (1m, 5m, 15m)", parts[0], parts[1], parts[2])
		}
	}

	vppVersion := "Unknown"
	vppCmd := exec.Command("vppctl", "show", "version")
	if vppOutput, err := vppCmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(vppOutput), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "vpp ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					vppVersion = parts[1]
				}
				break
			}
		}
	}

	birdVersion := "Unknown"
	birdCmd := exec.Command("ip", "netns", "exec", "dataplane", "birdc", "show", "status")
	if birdOutput, err := birdCmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(birdOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, "BIRD") && strings.Contains(line, "ready") {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "BIRD" && i+1 < len(parts) {
						birdVersion = fmt.Sprintf("BIRD %s ready", parts[i+1])
						break
					}
				}
				break
			}
		}
	}

	pvVersion := "Unknown"
	pvCmd := exec.Command("pathvector", "version")
	if pvOutput, err := pvCmd.CombinedOutput(); err == nil {
		pvVersion = strings.TrimSpace(string(pvOutput))
		if strings.Contains(pvVersion, "\n") {
			pvVersion = strings.Split(pvVersion, "\n")[0]
		}
	}

	fmt.Printf("FloofOS Version:      %s\n", floofVersion)
	fmt.Printf("Hostname:             %s\n", hostname)
	fmt.Printf("Uptime:               %s\n", uptimeStr)
	fmt.Printf("Kernel:               %s\n", kernelVersion)
	fmt.Printf("Load Average:         %s\n", loadAvg)
	fmt.Println()
	fmt.Println("---- Network Stack ----")
	fmt.Printf("VPP:                  %s\n", vppVersion)
	fmt.Printf("BIRD:                 %s\n", birdVersion)
	fmt.Printf("Pathvector:           %s\n", pvVersion)
	fmt.Println()
}

func showSystemTime() {
	fmt.Println()
	fmt.Println("System Time")
	fmt.Println()

	cmd := exec.Command("timedatectl", "show")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Timezone=") {
				fmt.Printf("Timezone:    %s\n", strings.TrimPrefix(line, "Timezone="))
			} else if strings.HasPrefix(line, "LocalRTC=") {
				fmt.Printf("Local RTC:   %s\n", strings.TrimPrefix(line, "LocalRTC="))
			} else if strings.HasPrefix(line, "NTP=") {
				val := strings.TrimPrefix(line, "NTP=")
				if val == "yes" {
					fmt.Println("NTP:         enabled")
				} else {
					fmt.Println("NTP:         disabled")
				}
			} else if strings.HasPrefix(line, "NTPSynchronized=") {
				val := strings.TrimPrefix(line, "NTPSynchronized=")
				if val == "yes" {
					fmt.Println("NTP Sync:    synchronized")
				} else {
					fmt.Println("NTP Sync:    not synchronized")
				}
			}
		}
	}

	dateCmd := exec.Command("date", "+%Y-%m-%d %H:%M:%S %Z")
	if dateOutput, err := dateCmd.Output(); err == nil {
		fmt.Printf("Current:     %s", string(dateOutput))
	}

	tzData, _ := os.ReadFile("/etc/timezone")
	if len(tzData) > 0 {
		fmt.Printf("Zone file:   %s", string(tzData))
	}

	fmt.Println()
}

func showCommitHistory() {
	fmt.Println("Commit History (last 50 commits):")
	fmt.Println()

	hasCommits := false
	for i := 0; i < maxRollbacks; i++ {
		rollbackPath := fmt.Sprintf("%s/%d", rollbackDir, i)
		if info, err := os.Stat(rollbackPath); err == nil {
			modTime := info.ModTime().Format("2006-01-02 15:04:05")
			current := ""
			if i == 0 {
				current = " (current)"
			}

			comment := ""
			if commentData, err := os.ReadFile(rollbackPath + ".comment"); err == nil && len(commentData) > 0 {
				comment = fmt.Sprintf(" \"%s\"", strings.TrimSpace(string(commentData)))
			}

			fmt.Printf("  %-3d %s%s%s\n", i, modTime, current, comment)
			hasCommits = true
		}
	}

	if !hasCommits {
		fmt.Println("  (no commit history)")
	}
	fmt.Println()
}

func showResource() {
	fmt.Println()
	fmt.Println("System Resources")
	fmt.Println()

	fmt.Println("---- CPU ----")

	cpuModel := "Unknown"
	cpuCores := "Unknown"
	cpuinfoData, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		lines := strings.Split(string(cpuinfoData), "\n")
		coreCount := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					cpuModel = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(line, "processor") {
				coreCount++
			}
		}
		if coreCount > 0 {
			cpuCores = fmt.Sprintf("%d", coreCount)
		}
	}

	cpuUsage := "Unknown"
	statData1, _ := os.ReadFile("/proc/stat")
	time.Sleep(100 * time.Millisecond)
	statData2, _ := os.ReadFile("/proc/stat")

	if len(statData1) > 0 && len(statData2) > 0 {
		lines1 := strings.Split(string(statData1), "\n")
		lines2 := strings.Split(string(statData2), "\n")

		if len(lines1) > 0 && len(lines2) > 0 {
			fields1 := strings.Fields(lines1[0])
			fields2 := strings.Fields(lines2[0])

			if len(fields1) >= 8 && len(fields2) >= 8 {
				var idle1, idle2, total1, total2 float64

				for i := 1; i < 8; i++ {
					val1, _ := strconv.ParseFloat(fields1[i], 64)
					val2, _ := strconv.ParseFloat(fields2[i], 64)
					total1 += val1
					total2 += val2
					if i == 4 {
						idle1 = val1
						idle2 = val2
					}
				}

				totalDiff := total2 - total1
				idleDiff := idle2 - idle1

				if totalDiff > 0 {
					usage := (1 - idleDiff/totalDiff) * 100
					cpuUsage = fmt.Sprintf("%.1f%%", usage)
				}
			}
		}
	}

	fmt.Printf("Model:                %s\n", cpuModel)
	fmt.Printf("Cores:                %s\n", cpuCores)
	fmt.Printf("Usage:                %s\n", cpuUsage)
	fmt.Println()

	fmt.Println("---- Memory ----")

	meminfoData, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		var memTotal, memAvailable, memFree, memUsed int64

		lines := strings.Split(string(meminfoData), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)

				switch fields[0] {
				case "MemTotal:":
					memTotal = value / 1024
				case "MemAvailable:":
					memAvailable = value / 1024
				case "MemFree:":
					memFree = value / 1024
				}
			}
		}

		memUsed = memTotal - memAvailable

		hugePagesTotal := 0
		hugePagesUsed := 0
		hugePagesSize := 0

		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.Atoi(fields[1])

				switch fields[0] {
				case "HugePages_Total:":
					hugePagesTotal = value
				case "HugePages_Free:":
					hugeFree := value
					hugePagesUsed = hugePagesTotal - hugeFree
				case "Hugepagesize:":
					hugePagesSize = value / 1024
				}
			}
		}

		fmt.Printf("Total:                %dGi\n", memTotal/1024)
		fmt.Printf("Used:                 %dGi\n", memUsed/1024)
		fmt.Printf("Free:                 %dGi\n", memFree/1024)
		fmt.Printf("Available:            %dGi\n", memAvailable/1024)

		if hugePagesTotal > 0 {
			hugeTotalMB := hugePagesTotal * hugePagesSize
			hugeUsedMB := hugePagesUsed * hugePagesSize
			hugeFreeMB := hugeTotalMB - hugeUsedMB
			fmt.Printf("HugePages (2MB):      %dMi total, %dMi used, %dMi free\n",
				hugeTotalMB, hugeUsedMB, hugeFreeMB)
		}
	}
	fmt.Println()

	fmt.Println("---- VPP Resources ----")

	vppMemCmd := exec.Command("vppctl", "show", "memory", "main-heap", "verbose")
	if vppMemOutput, err := vppMemCmd.CombinedOutput(); err == nil {
		output := string(vppMemOutput)
		lines := strings.Split(output, "\n")

		for _, line := range lines {
			if strings.Contains(line, "total:") {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "total:" && i+1 < len(parts) {
						fmt.Printf("Memory (main heap):   %s allocated", parts[i+1])

						for j := i; j < len(parts)-1; j++ {
							if parts[j] == "used:" && j+1 < len(parts) {
								fmt.Printf(", %s used\n", parts[j+1])
								break
							}
						}
						break
					}
				}
				break
			}
		}
	}

	vppThreadCmd := exec.Command("vppctl", "show", "threads")
	if vppThreadOutput, err := vppThreadCmd.CombinedOutput(); err == nil {
		output := string(vppThreadOutput)
		lines := strings.Split(output, "\n")

		threadCount := 0
		for _, line := range lines {
			if strings.Contains(line, "vpp_wk_") {
				threadCount++
			}
		}

		if threadCount > 0 {
			fmt.Printf("Worker Threads:       %d\n", threadCount)
		}
	}
	fmt.Println()

	fmt.Println("---- Network Interfaces ----")

	vppIntCmd := exec.Command("vppctl", "show", "interface")
	if vppIntOutput, err := vppIntCmd.CombinedOutput(); err == nil {
		output := string(vppIntOutput)
		lines := strings.Split(output, "\n")

		upCount := 0
		downCount := 0

		for _, line := range lines {
			if strings.Contains(line, " up ") {
				upCount++
			} else if strings.Contains(line, " down ") {
				downCount++
			}
		}

		fmt.Printf("Total Interfaces:     %d (%d up, %d down)\n", upCount+downCount, upCount, downCount)
	}
	fmt.Println()

	fmt.Println("---- Disk ----")

	dfCmd := exec.Command("df", "-h", "/")
	if dfOutput, err := dfCmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(dfOutput), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				fmt.Printf("Root Filesystem:      %s used / %s total (%s)\n",
					fields[2], fields[1], fields[4])
			}
		}
	}
	fmt.Println()
}

func cleanBIRDOutput(output string) string {
	lines := strings.Split(output, "\n")
	var cleaned []string

	for _, line := range lines {
		if strings.HasPrefix(line, "BIRD") ||
			strings.Contains(line, "ready") ||
			strings.HasPrefix(line, "birdc>") {
			continue
		}
		cleaned = append(cleaned, line)
	}

	return strings.Join(cleaned, "\n")
}

func printWithPager(output string) {
	lines := strings.Split(output, "\n")

	pageSize := 25

	if len(lines) <= pageSize {
		fmt.Print(output)
		return
	}

	for i := 0; i < pageSize && i < len(lines); i++ {
		fmt.Println(lines[i])
	}

	for i := pageSize; i < len(lines); i++ {
		fmt.Printf("-- more -- (%d/%d) [Enter=next line, q=quit] ", i, len(lines))

		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			var buf [1]byte
			os.Stdin.Read(buf[:])
			term.Restore(int(os.Stdin.Fd()), oldState)

			fmt.Print("\r\033[K")

			if buf[0] == 'q' || buf[0] == 'Q' {
				break
			}
			fmt.Println(lines[i])
		} else {
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			fmt.Print("\r\033[K")
			if strings.TrimSpace(input) == "q" {
				break
			}
			fmt.Println(lines[i])
		}
	}
}

func showTracerouteHelp() {
	fmt.Println("Possible completions:")
	fmt.Println("  <address>       Destination IP address or hostname")
	fmt.Println("  asn             Show AS for each hop")
	fmt.Println("  source          Source IP address")
	fmt.Println("  interface       Source interface")
}

func executePing(args []string) {
	if len(args) < 2 {
		fmt.Println("Error: Missing destination address")
		fmt.Println("Usage: ping <address> [options]")
		fmt.Println("Type 'ping ?' for help")
		return
	}

	executeVPP(args)
}

func executeTraceroute(args []string) {
	if len(args) < 2 {
		fmt.Println("Error: Missing destination address")
		fmt.Println("Usage: traceroute <address> [asn] [source <ip>] [interface <if>]")
		fmt.Println("Type 'traceroute ?' for help")
		return
	}

	destination := args[1]
	var sourceIP string
	var sourceInterface string
	showASN := false

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "asn":
			showASN = true
		case "source":
			if i+1 < len(args) {
				sourceIP = args[i+1]
				i++
			}
		case "interface":
			if i+1 < len(args) {
				sourceInterface = args[i+1]
				i++
			}
		}
	}

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-n")

	if showASN {
		cmdArgs = append(cmdArgs, "-A")
	}

	if sourceIP != "" {
		cmdArgs = append(cmdArgs, "-s", sourceIP)
	}

	if sourceInterface != "" {
		cmdArgs = append(cmdArgs, "-i", sourceInterface)
	}

	cmdArgs = append(cmdArgs, destination)

	cmd := exec.Command("traceroute", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing traceroute: %v\n", err)
	}
}

func loadHostname() {
	data, err := os.ReadFile("/etc/hostname")
	if err == nil {
		currentHostname = strings.TrimSpace(string(data))
		return
	}

	cmd := exec.Command("hostname")
	output, err := cmd.Output()
	if err == nil {
		currentHostname = strings.TrimSpace(string(output))
		return
	}

	currentHostname = "floof"
}

func loadUsers() (*UserDatabase, error) {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &UserDatabase{Users: []User{}}, nil
		}
		return nil, err
	}

	var db UserDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

func saveUsers(db *UserDatabase) error {
	os.MkdirAll(configDir, 0755)

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(usersFile, data, 0600)
}

func getCurrentUserInfo() (*User, error) {
	username := os.Getenv("FLOOFCTL_REAL_USER")

	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("LOGNAME")
	}

	if username == "" {
		uid := syscall.Getuid()
		passwdData, err := os.ReadFile("/etc/passwd")
		if err == nil {
			lines := strings.Split(string(passwdData), "\n")
			for _, line := range lines {
				fields := strings.Split(line, ":")
				if len(fields) >= 3 {
					userUID, _ := strconv.Atoi(fields[2])
					if userUID == uid {
						username = fields[0]
						break
					}
				}
			}
		}
	}

	if username == "" {
		return nil, fmt.Errorf("cannot determine current user")
	}

	if username == "root" {
		return &User{
			Username:  "root",
			Privilege: PrivilegeAdmin,
			Created:   "system",
		}, nil
	}

	db, err := loadUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range db.Users {
		if user.Username == username {
			return &user, nil
		}
	}

	return &User{
		Username:  username,
		Privilege: PrivilegeViewer,
		Created:   "unknown",
	}, nil
}

func requirePrivilege(required UserPrivilege) bool {
	if currentUser == nil {
		return false
	}
	return currentUser.Privilege >= required
}

func privilegeToString(priv UserPrivilege) string {
	switch priv {
	case PrivilegeAdmin:
		return "admin"
	case PrivilegeOperator:
		return "operator"
	case PrivilegeViewer:
		return "viewer"
	default:
		return "unknown"
	}
}

func stringToPrivilege(s string) (UserPrivilege, error) {
	switch strings.ToLower(s) {
	case "admin":
		return PrivilegeAdmin, nil
	case "operator":
		return PrivilegeOperator, nil
	case "viewer":
		return PrivilegeViewer, nil
	default:
		return 0, fmt.Errorf("invalid privilege class: %s (must be admin, operator, or viewer)", s)
	}
}

func setHostname(newHostname string) {
	if newHostname == "" {
		fmt.Println("Error: Hostname cannot be empty")
		return
	}

	for _, c := range newHostname {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			fmt.Printf("Error: Invalid hostname '%s' (use only alphanumeric, dash, underscore)\n", newHostname)
			return
		}
	}

	fmt.Printf("Setting hostname to '%s'...\n", newHostname)

	cmd := exec.Command("hostnamectl", "set-hostname", newHostname)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if err := os.WriteFile("/etc/hostname", []byte(newHostname+"\n"), 0644); err != nil {
			fmt.Printf("Error setting hostname: %v\n", err)
			return
		}

		hostsData, _ := os.ReadFile("/etc/hosts")
		hostsContent := string(hostsData)
		if !strings.Contains(hostsContent, newHostname) {
			hostsLine := fmt.Sprintf("127.0.1.1\t%s\n", newHostname)
			hostsContent = hostsLine + hostsContent
			os.WriteFile("/etc/hosts", []byte(hostsContent), 0644)
		}

		exec.Command("hostname", newHostname).Run()
	} else if len(output) > 0 {
		_ = output
	}

	currentHostname = newHostname

	auditLogConfig(fmt.Sprintf("Set hostname to '%s'", newHostname))
	fmt.Printf("Success: Hostname set to '%s'\n", newHostname)
}

const (
	backupBaseDir = "/etc/floofos-config"
	backupDir     = "/etc/floofos-config/backups"
	rollbackDir   = "/etc/floofos-config/commits"
	maxRollbacks  = 50
)

var configFiles = []string{
	"/etc/pathvector.yml",
	"/etc/vpp/config/head.vpp",
	"/etc/vpp/config/vppcfg.vpp",
	"/etc/vpp/config/tail.vpp",
	"/etc/vpp/dataplane.yaml",
	"/etc/floofctl/users.json",
	"/etc/floofctl/log.conf",
	"/etc/hostname",
	"/etc/timezone",
	"/etc/nftables.d/floofos.nft",
	"/etc/snmp/snmpd-dataplane.conf",
	"/etc/chrony/chrony.conf",
	"/etc/resolv.conf",
	"/etc/ssh/sshd_config",
}

func initBackupSystem() {
	os.MkdirAll(backupDir, 0755)
	os.MkdirAll(rollbackDir, 0755)
}

func createAutoBackup(comment string) {
	initBackupSystem()

	for i := maxRollbacks - 2; i >= 0; i-- {
		oldPath := fmt.Sprintf("%s/%d", rollbackDir, i)
		newPath := fmt.Sprintf("%s/%d", rollbackDir, i+1)

		os.RemoveAll(newPath)

		if _, err := os.Stat(oldPath); err == nil {
			os.Rename(oldPath, newPath)
			os.Rename(oldPath+".comment", newPath+".comment")
		}
	}

	rollback0 := fmt.Sprintf("%s/0", rollbackDir)
	os.MkdirAll(rollback0, 0755)

	for _, file := range configFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			filename := getFilename(file)
			os.WriteFile(fmt.Sprintf("%s/%s", rollback0, filename), data, 0644)
		}
	}

	if comment != "" {
		os.WriteFile(rollback0+".comment", []byte(comment), 0644)
	}
}

func backupExport(name string, exportPath string) {
	initBackupSystem()

	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		fmt.Println("Error: Invalid backup name")
		return
	}

	os.MkdirAll(exportPath, 0755)

	tarFile := fmt.Sprintf("%s/%s.tar.gz", exportPath, name)

	if _, err := os.Stat(tarFile); err == nil {
		fmt.Printf("Error: Backup '%s' already exists at %s\n", name, tarFile)
		return
	}

	tempDir := fmt.Sprintf("/tmp/floofos-backup-%s", name)
	os.RemoveAll(tempDir)
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	fileCount := 0
	for _, file := range configFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			filename := getFilename(file)
			os.WriteFile(fmt.Sprintf("%s/%s", tempDir, filename), data, 0644)
			fileCount++
		}
	}

	if fileCount == 0 {
		fmt.Println("Error: No config files found to backup")
		return
	}

	tarCmd := exec.Command("tar", "-czf", tarFile, "-C", tempDir, ".")
	if err := tarCmd.Run(); err != nil {
		fmt.Printf("Error creating backup archive: %v\n", err)
		return
	}

	auditLogInfo(fmt.Sprintf("Backup exported: %s to %s", name, tarFile))
	fmt.Printf("Backup exported: %s\n", tarFile)
	fmt.Printf("Files backed up: %d\n", fileCount)
}

func backupImport(name string, importPath string) {
	initBackupSystem()

	var tarFile string
	if importPath != "" {
		if strings.HasSuffix(importPath, ".tar.gz") {
			tarFile = importPath
		} else {
			tarFile = fmt.Sprintf("%s/%s.tar.gz", importPath, name)
		}
	} else {
		tarFile = fmt.Sprintf("%s/%s.tar.gz", backupDir, name)
	}

	if _, err := os.Stat(tarFile); err != nil {
		fmt.Printf("Error: Backup '%s' not found\n", tarFile)
		fmt.Println("Use 'show backups' to list available backups")
		return
	}

	tempDir := fmt.Sprintf("/tmp/floofos-restore-%d", time.Now().Unix())
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	tarCmd := exec.Command("tar", "-xzf", tarFile, "-C", tempDir)
	if err := tarCmd.Run(); err != nil {
		fmt.Printf("Error extracting backup archive: %v\n", err)
		return
	}

	restoredCount := 0
	for _, file := range configFiles {
		filename := getFilename(file)
		backupFile := fmt.Sprintf("%s/%s", tempDir, filename)

		data, err := os.ReadFile(backupFile)
		if err != nil {
			continue
		}

		dir := filepath.Dir(file)
		os.MkdirAll(dir, 0755)

		if err := os.WriteFile(file, data, 0644); err != nil {
			fmt.Printf("Warning: Failed to restore %s: %v\n", file, err)
			continue
		}
		restoredCount++
	}

	if restoredCount == 0 {
		fmt.Println("Error: No files were restored from backup")
		return
	}

	hasUnsavedChanges = true
	auditLogInfo(fmt.Sprintf("Backup imported: %s (%d files)", name, restoredCount))
	fmt.Printf("Configuration imported from: %s\n", tarFile)
	fmt.Printf("Files restored: %d\n", restoredCount)
	fmt.Println()
	fmt.Println("Run 'commit' to apply changes")
	fmt.Println("Reboot required after commit: run 'system reboot'")
}

func restoreRollback(num int) {
	rollbackPath := fmt.Sprintf("%s/%d", rollbackDir, num)

	if _, err := os.Stat(rollbackPath); err != nil {
		fmt.Printf("Error: Rollback %d not found\n", num)
		fmt.Println("Type 'rollback ?' for available rollback points")
		return
	}

	if !restoreConfigFiles(rollbackPath) {
		fmt.Println("Rollback failed")
		return
	}

	hasUnsavedChanges = true
	fmt.Println("Configuration loaded from rollback point")
	fmt.Println("Run 'commit' to apply changes")
	fmt.Println("Reboot required after commit: run 'system reboot'")
}

func restoreConfigFiles(sourcePath string) bool {
	for _, file := range configFiles {
		filename := getFilename(file)
		backupFile := fmt.Sprintf("%s/%s", sourcePath, filename)

		data, err := os.ReadFile(backupFile)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			fmt.Printf("Error: Failed to read %s\n", filename)
			return false
		}

		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Error: Failed to create directory for %s\n", filename)
			return false
		}

		err = os.WriteFile(file, data, 0644)
		if err != nil {
			fmt.Printf("Error: Failed to write %s\n", filename)
			return false
		}
	}
	return true
}

func isLoggingGlobalEnabled() bool {
	data, err := os.ReadFile(logConfFile)
	if err != nil {
		return true
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LOGGING_GLOBAL_ENABLED=") {
			value := strings.TrimPrefix(line, "LOGGING_GLOBAL_ENABLED=")
			return value == "true"
		}
	}
	return true
}

func isLoggingSystemEnabled() bool {
	data, err := os.ReadFile(logConfFile)
	if err != nil {
		return true
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LOGGING_SYSTEM_ENABLED=") {
			value := strings.TrimPrefix(line, "LOGGING_SYSTEM_ENABLED=")
			return value == "true"
		}
	}
	return true
}

func isLoggingBGPEnabled() bool {
	if !isLoggingGlobalEnabled() {
		return false
	}

	data, err := os.ReadFile(logConfFile)
	if err != nil {
		return true
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "LOGGING_BGP_ENABLED=") {
			value := strings.TrimPrefix(line, "LOGGING_BGP_ENABLED=")
			return value == "true"
		}
	}
	return true
}

func setLogConfig(key string, value bool) error {
	os.MkdirAll(filepath.Dir(logConfFile), 0755)

	var content string
	data, err := os.ReadFile(logConfFile)
	if err == nil {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	found := false
	newValue := "false"
	if value {
		newValue = "true"
	}

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = key + "=" + newValue
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, key+"="+newValue)
	}

	return os.WriteFile(logConfFile, []byte(strings.Join(lines, "\n")), 0644)
}

func setLogGlobalEnable() {
	cmd := exec.Command("systemctl", "start", "rsyslog")
	cmd.Run()
	cmd = exec.Command("systemctl", "enable", "rsyslog")
	cmd.Run()

	if err := setLogConfig("LOGGING_GLOBAL_ENABLED", true); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	if err := setLogConfig("LOGGING_SYSTEM_ENABLED", true); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	if err := setLogConfig("LOGGING_BGP_ENABLED", true); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}

	fmt.Println("All logging systems enabled")
}

func setLogGlobalDisable() {
	fmt.Println("WARNING: This will disable ALL logging systems")
	fmt.Println("  - System audit logs will stop")
	fmt.Println("  - BGP routing logs will stop")
	fmt.Println("  - Critical events will not be recorded")
	fmt.Println()
	fmt.Println("To proceed, run: set all logging disable confirm")
}

func setLogGlobalDisableConfirmed() {

	cmd := exec.Command("systemctl", "stop", "rsyslog")
	cmd.Run()
	cmd = exec.Command("systemctl", "disable", "rsyslog")
	cmd.Run()

	if err := setLogConfig("LOGGING_GLOBAL_ENABLED", false); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	if err := setLogConfig("LOGGING_SYSTEM_ENABLED", false); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	if err := setLogConfig("LOGGING_BGP_ENABLED", false); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}

	fmt.Println("All logging systems disabled")
}

func setLogSystemEnable() {
	if err := setLogConfig("LOGGING_SYSTEM_ENABLED", true); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	fmt.Println("Audit logging enabled")
}

func setLogSystemDisable() {
	if err := setLogConfig("LOGGING_SYSTEM_ENABLED", false); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	fmt.Println("Audit logging disabled")
}

func setLogBGPEnable() {
	if err := setLogConfig("LOGGING_BGP_ENABLED", true); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	fmt.Println("BGP log viewer enabled")
}

func setLogBGPDisable() {
	if err := setLogConfig("LOGGING_BGP_ENABLED", false); err != nil {
		fmt.Println("Error: Failed to update configuration")
		return
	}
	fmt.Println("BGP log viewer disabled")
}

func listNamedBackups() {
	fmt.Println("Available backups:")

	entries, err := os.ReadDir(backupDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("  (no backups)")
		return
	}

	found := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tar.gz") {
			info, _ := entry.Info()
			modTime := info.ModTime().Format("2006-01-02 15:04:05")
			name := strings.TrimSuffix(entry.Name(), ".tar.gz")
			size := info.Size() / 1024
			fmt.Printf("  %-25s %s  %dKB\n", name, modTime, size)
			found = true
		}
	}
	if !found {
		fmt.Println("  (no backups)")
	}
	fmt.Println()
}

func showAllBackups() {
	fmt.Println("Exported Backups:")
	fmt.Printf("  Location: %s\n", backupDir)
	fmt.Println()

	entries, err := os.ReadDir(backupDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("  (no backups)")
	} else {
		found := false
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tar.gz") {
				info, _ := entry.Info()
				modTime := info.ModTime().Format("2006-01-02 15:04:05")
				name := strings.TrimSuffix(entry.Name(), ".tar.gz")
				size := info.Size() / 1024
				fmt.Printf("  %-25s %s  %dKB\n", name, modTime, size)
				found = true
			}
		}
		if !found {
			fmt.Println("  (no backups)")
		}
	}

	fmt.Println()
	fmt.Println("Rollback History (last 50 commits):")

	hasRollbacks := false
	for i := 0; i < maxRollbacks; i++ {
		rollbackPath := fmt.Sprintf("%s/%d", rollbackDir, i)
		if info, err := os.Stat(rollbackPath); err == nil {
			modTime := info.ModTime().Format("2006-01-02 15:04:05")
			current := ""
			if i == 0 {
				current = " (current)"
			}

			comment := ""
			if commentData, err := os.ReadFile(rollbackPath + ".comment"); err == nil {
				comment = fmt.Sprintf(" \"%s\"", string(commentData))
			}

			fmt.Printf("  %-3d %s%s%s\n", i, modTime, current, comment)
			hasRollbacks = true
		}
	}

	if !hasRollbacks {
		fmt.Println("  (no rollback history)")
	}

	fmt.Println()
}

func showRollbackHelp() {
	fmt.Println("rollback - Load one of the 50 most recent committed configurations")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  rollback         Load last committed configuration (rollback 0)")
	fmt.Println("  rollback <0-49>  Load specific rollback point")
	fmt.Println()
	fmt.Println("Available rollback points:")

	hasRollbacks := false
	for i := 0; i < 10; i++ {
		rollbackPath := fmt.Sprintf("%s/%d", rollbackDir, i)
		if info, err := os.Stat(rollbackPath); err == nil {
			modTime := info.ModTime().Format("2006-01-02 15:04:05")
			current := ""
			if i == 0 {
				current = " (current)"
			}

			comment := ""
			if commentData, err := os.ReadFile(rollbackPath + ".comment"); err == nil {
				comment = fmt.Sprintf(" \"%s\"", string(commentData))
			}

			fmt.Printf("  %-3d %s%s%s\n", i, modTime, current, comment)
			hasRollbacks = true
		}
	}

	if !hasRollbacks {
		fmt.Println("  (no rollback history)")
	} else {
		count := 0
		for i := 0; i < maxRollbacks; i++ {
			rollbackPath := fmt.Sprintf("%s/%d", rollbackDir, i)
			if _, err := os.Stat(rollbackPath); err == nil {
				count++
			}
		}
		if count > 10 {
			fmt.Printf("  ... and %d more (use 'show backups' to see all)\n", count-10)
		}
	}

	fmt.Println()
}

func getFilename(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func showTrafficInterface(ifname string) {
	testCmd := exec.Command("vppctl", "show", "interface", ifname)
	testOutput, err := testCmd.CombinedOutput()

	validInterface := false
	if err == nil && len(testOutput) > 0 {
		outputStr := string(testOutput)
		if strings.Contains(outputStr, "unknown input") {
			validInterface = false
		} else if strings.Contains(outputStr, "rx packets") || strings.Contains(outputStr, "tx packets") {
			validInterface = true
		}
	}

	if !validInterface {
		fmt.Printf("Error: Interface '%s' not found\n", ifname)
		fmt.Println()
		fmt.Println("Available interfaces:")
		listCmd := exec.Command("vppctl", "show", "interface")
		if output, err := listCmd.CombinedOutput(); err == nil {
			lines := strings.Split(string(output), "\n")
			foundAny := false
			for _, line := range lines {
				if strings.Contains(line, " up ") || strings.Contains(line, " down ") {
					fields := strings.Fields(line)
					if len(fields) > 0 {
						fmt.Printf("  %s\n", fields[0])
						foundAny = true
					}
				}
			}
			if !foundAny {
				fmt.Println("  (no interfaces found)")
			}
		} else {
			fmt.Println("  (unable to list interfaces)")
		}
		fmt.Println()
		return
	}

	if err := ui.Init(); err != nil {
		fmt.Printf("Error: Failed to initialize UI: %v\n", err)
		return
	}
	defer ui.Close()

	rxChart := widgets.NewPlot()
	rxChart.Title = fmt.Sprintf("Interface %s - Receive Traffic (Kbps)", ifname)
	rxChart.Data = make([][]float64, 1)
	rxChart.Data[0] = []float64{0}
	rxChart.DataLabels = []string{"RX"}
	rxChart.LineColors[0] = ui.ColorRed
	rxChart.DotMarkerRune = '•'
	rxChart.AxesColor = ui.ColorWhite
	rxChart.SetRect(0, 0, 100, 12)

	txChart := widgets.NewPlot()
	txChart.Title = "Transmit Traffic (Kbps)"
	txChart.Data = make([][]float64, 1)
	txChart.Data[0] = []float64{0}
	txChart.DataLabels = []string{"TX"}
	txChart.LineColors[0] = ui.ColorBlue
	txChart.DotMarkerRune = '•'
	txChart.AxesColor = ui.ColorWhite
	txChart.SetRect(0, 12, 100, 24)

	stats := widgets.NewParagraph()
	stats.Title = "Statistics"
	stats.Text = "Initializing..."
	stats.SetRect(0, 24, 100, 32)

	maxDataPoints := 155
	rxHistory := []float64{0, 0}
	txHistory := []float64{0, 0}

	var prevStats *InterfaceStats
	paused := false

	rxChart.Data[0] = []float64{0, 0}
	txChart.Data[0] = []float64{0, 0}

	func() {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		ui.Render(rxChart, txChart, stats)
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	uiEvents := ui.PollEvents()

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return
			case "r":
				rxHistory = []float64{0, 0}
				txHistory = []float64{0, 0}
				rxChart.Data = make([][]float64, 1)
				rxChart.Data[0] = []float64{0, 0}
				txChart.Data = make([][]float64, 1)
				txChart.Data[0] = []float64{0, 0}
				prevStats = nil
				func() {
					defer func() {
						if r := recover(); r != nil {
							return
						}
					}()
					ui.Render(rxChart, txChart, stats)
				}()
			case "p":
				paused = !paused
				if paused {
					stats.Title = "Statistics (PAUSED)"
				} else {
					stats.Title = "Statistics"
				}
				func() {
					defer func() {
						if r := recover(); r != nil {
							return
						}
					}()
					ui.Render(rxChart, txChart, stats)
				}()
			}

		case <-ticker.C:
			if paused {
				continue
			}

			currentStats := getVPPInterfaceStats(ifname)

			var rxBps, txBps, rxPps, txPps float64

			if prevStats != nil {
				rxBps = float64(currentStats.RxBytes-prevStats.RxBytes) * 8.0
				txBps = float64(currentStats.TxBytes-prevStats.TxBytes) * 8.0

				rxPps = float64(currentStats.RxPackets - prevStats.RxPackets)
				txPps = float64(currentStats.TxPackets - prevStats.TxPackets)
			}

			rxHistory = append(rxHistory, rxBps/1e3)
			txHistory = append(txHistory, txBps/1e3)
			if len(rxHistory) > maxDataPoints {
				rxHistory = rxHistory[1:]
				txHistory = txHistory[1:]
			}

			if len(rxHistory) >= 2 {
				if len(rxChart.Data) == 0 {
					rxChart.Data = make([][]float64, 1)
					txChart.Data = make([][]float64, 1)
				}
				rxChart.Data[0] = make([]float64, len(rxHistory))
				txChart.Data[0] = make([]float64, len(txHistory))
				copy(rxChart.Data[0], rxHistory)
				copy(txChart.Data[0], txHistory)
			} else {
				rxChart.Data = make([][]float64, 1)
				rxChart.Data[0] = []float64{0, 0}
				txChart.Data = make([][]float64, 1)
				txChart.Data[0] = []float64{0, 0}
			}

			rxRate, rxUnit := formatTraffic(rxBps)
			txRate, txUnit := formatTraffic(txBps)

			statsText := fmt.Sprintf("RX: %.2f %s | TX: %.2f %s | Link Speed: %.1f Gbps\n", rxRate, rxUnit, txRate, txUnit, currentStats.LinkSpeedGbps)
			statsText += fmt.Sprintf("Packets/sec: %.0f pps (RX), %.0f pps (TX)\n", rxPps, txPps)
			statsText += fmt.Sprintf("Drops: %d | Errors: %d\n", currentStats.Drops, currentStats.Errors)
			statsText += "\nPress 'q' to exit, 'r' to reset, 'p' to pause/resume"
			stats.Text = statsText

			prevStats = &currentStats

			termWidth, termHeight := ui.TerminalDimensions()
			rxChart.SetRect(0, 0, termWidth, (termHeight-7)/2)
			txChart.SetRect(0, (termHeight-7)/2, termWidth, termHeight-7)
			stats.SetRect(0, termHeight-7, termWidth, termHeight)

			func() {
				defer func() {
					if r := recover(); r != nil {
						return
					}
				}()
				ui.Render(rxChart, txChart, stats)
			}()
		}
	}
}

func getVPPInterfaceStats(ifname string) InterfaceStats {
	stats := InterfaceStats{}

	cmd := exec.Command("vppctl", "show", "interface", ifname)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return stats
	}

	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		fields := strings.Fields(lineTrimmed)

		if len(fields) == 0 {
			continue
		}

		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "rx" && fields[i+1] == "packets" && i+2 < len(fields) {
				if val, err := strconv.ParseUint(fields[i+2], 10, 64); err == nil {
					stats.RxPackets = val
				}
			}
			if fields[i] == "rx" && fields[i+1] == "bytes" && i+2 < len(fields) {
				if val, err := strconv.ParseUint(fields[i+2], 10, 64); err == nil {
					stats.RxBytes = val
				}
			}
			if fields[i] == "tx" && fields[i+1] == "packets" && i+2 < len(fields) {
				if val, err := strconv.ParseUint(fields[i+2], 10, 64); err == nil {
					stats.TxPackets = val
				}
			}
			if fields[i] == "tx" && fields[i+1] == "bytes" && i+2 < len(fields) {
				if val, err := strconv.ParseUint(fields[i+2], 10, 64); err == nil {
					stats.TxBytes = val
				}
			}
			if fields[i] == "drops" && i+1 < len(fields) {
				if val, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
					stats.Drops += val
				}
			}
		}

		if strings.Contains(lineTrimmed, "rx-error") || strings.Contains(lineTrimmed, "tx-error") {
			for i, field := range fields {
				if (field == "rx-error" || field == "tx-error") && i+1 < len(fields) {
					if errorCount, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
						stats.Errors += errorCount
					}
				}
			}
		}
	}

	stats.LinkSpeedGbps = getLinkSpeedFromLinux(ifname)

	return stats
}

func getLinkSpeedFromLinux(vppIfname string) float64 {

	maxSpeed := 0.0

	lsCmd := exec.Command("ip", "netns", "exec", "dataplane", "ls", "/sys/class/net")
	output, err := lsCmd.CombinedOutput()
	if err != nil {
		return 1.0
	}

	linuxInterfaces := strings.Fields(string(output))

	for _, linuxIf := range linuxInterfaces {
		if linuxIf == "lo" {
			continue
		}

		cmd := exec.Command("ip", "netns", "exec", "dataplane", "ethtool", linuxIf)
		if output, err := cmd.CombinedOutput(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Speed:") {
					fields := strings.Fields(line)
					for i, field := range fields {
						if field == "Speed:" && i+1 < len(fields) {
							speedStr := fields[i+1]
							speedStr = strings.TrimSuffix(speedStr, "Mb/s")
							speedStr = strings.TrimSuffix(speedStr, "Gb/s")
							if speed, err := strconv.ParseFloat(speedStr, 64); err == nil {
								var detectedSpeed float64
								if strings.Contains(fields[i+1], "Gb/s") {
									detectedSpeed = speed
								} else if strings.Contains(fields[i+1], "Mb/s") {
									detectedSpeed = speed / 1000.0
								}
								if detectedSpeed > maxSpeed {
									maxSpeed = detectedSpeed
								}
							}
						}
					}
				}
			}
		}

		cmd2 := exec.Command("ip", "netns", "exec", "dataplane", "cat", fmt.Sprintf("/sys/class/net/%s/speed", linuxIf))
		if output, err := cmd2.CombinedOutput(); err == nil {
			speedMbps, _ := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
			speedGbps := speedMbps / 1000.0
			if speedGbps > 0 && speedGbps > maxSpeed {
				maxSpeed = speedGbps
			}
		}
	}

	if maxSpeed == 0.01 {
		maxSpeed = 1.0
	}

	if maxSpeed > 0 {
		return maxSpeed
	}
	return 1.0
}

func formatTraffic(bitsPerSec float64) (float64, string) {
	if bitsPerSec >= 1e9 {
		return bitsPerSec / 1e9, "Gbps"
	} else if bitsPerSec >= 1e6 {
		return bitsPerSec / 1e6, "Mbps"
	} else if bitsPerSec >= 1e3 {
		return bitsPerSec / 1e3, "Kbps"
	}
	return bitsPerSec, "bps"
}

func handleSecuritySetCommands(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: set security <firewall|fail2ban|ssh-key|ssh-password-auth>")
		return
	}

	switch args[0] {
	case "firewall":
		if len(args) < 2 {
			fmt.Println("Usage: set security firewall <enable|disable|rule>")
			return
		}

		switch args[1] {
		case "enable":
			if err := security.EnableFirewall(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to enable firewall: %v", err))
			} else {
				fmt.Println("Firewall enabled successfully")
				auditLogInfo("Firewall enabled")
			}

		case "disable":
			if err := security.DisableFirewall(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to disable firewall: %v", err))
			} else {
				fmt.Println("Firewall disabled successfully")
				auditLogInfo("Firewall disabled")
			}

		case "rule":
			if len(args) < 3 {
				fmt.Println("Usage: set security firewall rule <name> protocol <tcp|udp> port <port> [src-address <ip/cidr>] action <accept|drop>")
				fmt.Println("\nExamples:")
				fmt.Println("  set security firewall rule api-server protocol tcp port 8080 action accept")
				fmt.Println("  set security firewall rule mgmt-only protocol tcp port 8080 src-address 10.0.0.0/8 action accept")
				return
			}

			ruleName := args[2]
			protocol := ""
			port := ""
			srcAddress := ""
			action := ""

			i := 3
			for i < len(args) {
				switch args[i] {
				case "protocol":
					if i+1 < len(args) {
						protocol = args[i+1]
						i += 2
					} else {
						fmt.Println("Error: protocol requires a value")
						return
					}
				case "port":
					if i+1 < len(args) {
						port = args[i+1]
						i += 2
					} else {
						fmt.Println("Error: port requires a value")
						return
					}
				case "src-address":
					if i+1 < len(args) {
						srcAddress = args[i+1]
						i += 2
					} else {
						fmt.Println("Error: src-address requires a value")
						return
					}
				case "action":
					if i+1 < len(args) {
						action = args[i+1]
						i += 2
					} else {
						fmt.Println("Error: action requires a value")
						return
					}
				default:
					fmt.Printf("Error: unknown parameter '%s'\n", args[i])
					return
				}
			}

			if action == "" {
				fmt.Println("Error: action is required")
				fmt.Println("Usage: set security firewall rule <name> protocol <tcp|udp> port <port> [src-address <ip/cidr>] action <accept|drop>")
				return
			}

			if protocol == "" || port == "" {
				fmt.Println("Error: protocol and port are required")
				fmt.Println("Usage: set security firewall rule <name> protocol <tcp|udp> port <port> [src-address <ip/cidr>] action <accept|drop>")
				return
			}

			if err := security.AddFirewallRule(ruleName, protocol, port, srcAddress, action); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to add firewall rule: %v", err))
			} else {
				fmt.Printf("Firewall rule '%s' added successfully\n", ruleName)
				auditLogInfo(fmt.Sprintf("Added firewall rule: %s", ruleName))
			}

		default:
			fmt.Println("Unknown firewall command. Use: enable, disable, rule")
		}

	case "fail2ban":
		if len(args) < 2 {
			fmt.Println("Usage: set security fail2ban <enable|disable|maxretry|bantime>")
			return
		}

		switch args[1] {
		case "enable":
			if err := security.EnableFail2ban(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to enable fail2ban: %v", err))
			} else {
				fmt.Println("Fail2ban enabled successfully")
				auditLogInfo("Fail2ban enabled")
			}

		case "disable":
			if err := security.DisableFail2ban(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to disable fail2ban: %v", err))
			} else {
				fmt.Println("Fail2ban disabled successfully")
				auditLogInfo("Fail2ban disabled")
			}

		case "maxretry":
			if len(args) < 3 {
				fmt.Println("Usage: set security fail2ban maxretry <number>")
				return
			}
			maxRetry, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Printf("Error: Invalid number: %v\n", err)
				return
			}

			if err := security.SetMaxRetry(maxRetry); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to set maxretry: %v", err))
			} else {
				fmt.Printf("Fail2ban maxretry set to %d\n", maxRetry)
				auditLogInfo(fmt.Sprintf("Set fail2ban maxretry: %d", maxRetry))
			}

		case "bantime":
			if len(args) < 3 {
				fmt.Println("Usage: set security fail2ban bantime <seconds>")
				return
			}
			bantime, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Printf("Error: Invalid number: %v\n", err)
				return
			}

			if err := security.SetBanTime(bantime); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to set bantime: %v", err))
			} else {
				fmt.Printf("Fail2ban bantime set to %d seconds\n", bantime)
				auditLogInfo(fmt.Sprintf("Set fail2ban bantime: %d", bantime))
			}

		default:
			fmt.Println("Unknown fail2ban command. Use: enable, disable, maxretry, bantime")
		}

	case "ssh-key":
		if len(args) < 4 || args[2] != "key" {
			fmt.Println("Usage: set security ssh-key <username> key <public-key>")
			return
		}
		username := args[1]
		publicKey := strings.Join(args[3:], " ")

		if err := security.AddSSHKey(username, publicKey); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to add SSH key for %s: %v", username, err))
		} else {
			fmt.Printf("SSH public key added for user '%s'\n", username)
			auditLogInfo(fmt.Sprintf("Added SSH key for user: %s", username))
		}

	case "ssh-password-auth":
		if len(args) < 2 {
			fmt.Println("Usage: set security ssh-password-auth <enable|disable>")
			return
		}

		switch args[1] {
		case "enable":
			if err := security.EnablePasswordAuth(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to enable password auth: %v", err))
			} else {
				fmt.Println("SSH password authentication enabled")
				auditLogInfo("Enabled SSH password authentication")
			}

		case "disable":
			if err := security.DisablePasswordAuth(); err != nil {
				fmt.Printf("Error: %v\n", err)
				auditLogError(fmt.Sprintf("Failed to disable password auth: %v", err))
			} else {
				fmt.Println("SSH password authentication disabled")
				auditLogInfo("Disabled SSH password authentication")
			}

		default:
			fmt.Println("Usage: set security ssh-password-auth <enable|disable>")
		}

	default:
		fmt.Println("Unknown security command. Use: firewall, fail2ban, ssh-key, ssh-password-auth")
	}
}

func handleSecurityShowCommands(args []string) {
	if len(args) == 0 {
		fmt.Println()
		fmt.Println("Security Status")
		fmt.Println()

		status, _ := security.GetFirewallStatus()
		fmt.Println("Firewall:")
		for _, line := range strings.Split(status, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Println("  " + line)
			}
		}
		fmt.Println()

		f2bStatus, _ := security.GetFail2banStatus()
		fmt.Println("Fail2ban:")
		for _, line := range strings.Split(f2bStatus, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Println("  " + line)
			}
		}
		fmt.Println()

		sshConfig, _ := security.GetSSHConfig()
		fmt.Println("SSH:")
		for _, line := range strings.Split(sshConfig, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Println("  " + line)
			}
		}
		return
	}

	switch args[0] {
	case "firewall":
		if len(args) >= 2 {
			switch args[1] {
			case "status":
				status, err := security.GetFirewallStatus()
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Printf("Firewall Status: %s\n", status)
				}

			case "rules":
				rules, err := security.ListFirewallRules()
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println(rules)
				}

			default:
				status, _ := security.GetFirewallStatus()
				fmt.Printf("Firewall Status: %s\n", status)
			}
		} else {
			status, _ := security.GetFirewallStatus()
			fmt.Printf("Firewall Status: %s\n", status)
		}

	case "fail2ban":
		if len(args) >= 2 {
			switch args[1] {
			case "status":
				status, err := security.GetFail2banStatus()
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println(status)
				}

			case "banned":
				banned, err := security.GetBannedIPs()
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println(banned)
				}

			default:
				status, _ := security.GetFail2banStatus()
				fmt.Println(status)
			}
		} else {
			status, _ := security.GetFail2banStatus()
			fmt.Println(status)
		}

	case "ssh-keys":
		keys, err := security.ListSSHKeys()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(keys)
		}

	case "ssh-config":
		config, err := security.GetSSHConfig()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(config)
		}

	default:
		fmt.Println("Unknown security show command. Use: firewall, fail2ban, ssh-keys, ssh-config")
	}
}

func handleSecurityDeleteCommands(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: delete security <firewall|ssh-key>")
		return
	}

	switch args[0] {
	case "firewall":
		if len(args) < 3 || args[1] != "rule" {
			fmt.Println("Usage: delete security firewall rule <name>")
			return
		}
		ruleName := args[2]

		if err := security.DeleteFirewallRule(ruleName); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to delete firewall rule %s: %v", ruleName, err))
		} else {
			fmt.Printf("Firewall rule '%s' deleted\n", ruleName)
			auditLogInfo(fmt.Sprintf("Deleted firewall rule: %s", ruleName))
		}

	case "ssh-key":
		if len(args) < 2 {
			fmt.Println("Usage: delete security ssh-key <username>")
			return
		}
		username := args[1]

		if err := security.DeleteSSHKey(username); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to delete SSH key for %s: %v", username, err))
		} else {
			fmt.Printf("SSH keys deleted for user '%s'\n", username)
			auditLogInfo(fmt.Sprintf("Deleted SSH keys for user: %s", username))
		}

	default:
		fmt.Println("Unknown security delete command. Use: firewall rule, ssh-key")
	}
}

func handleSNMPSetCommands(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: set snmp <enable|disable|community|location|contact|polling-interval>")
		return
	}

	switch args[0] {
	case "enable":
		if err := snmp.EnableSNMP(); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to enable SNMP: %v", err))
		} else {
			fmt.Println("SNMP agent enabled successfully")
			auditLogInfo("SNMP agent enabled")
		}

	case "disable":
		if err := snmp.DisableSNMP(); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to disable SNMP: %v", err))
		} else {
			fmt.Println("SNMP agent disabled successfully")
			auditLogInfo("SNMP agent disabled")
		}

	case "community":
		if len(args) < 2 {
			fmt.Println("Usage: set snmp community <string>")
			return
		}
		community := args[1]

		if err := snmp.SetCommunity(community); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to set SNMP community: %v", err))
		} else {
			fmt.Printf("SNMP community set to '%s'\n", community)
			auditLogInfo(fmt.Sprintf("Set SNMP community: %s", community))
		}

	case "location":
		if len(args) < 2 {
			fmt.Println("Usage: set snmp location <string>")
			return
		}
		location := strings.Join(args[1:], " ")

		if err := snmp.SetLocation(location); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to set SNMP location: %v", err))
		} else {
			fmt.Printf("SNMP location set to '%s'\n", location)
			auditLogInfo(fmt.Sprintf("Set SNMP location: %s", location))
		}

	case "contact":
		if len(args) < 2 {
			fmt.Println("Usage: set snmp contact <email>")
			return
		}
		contact := args[1]

		if err := snmp.SetContact(contact); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to set SNMP contact: %v", err))
		} else {
			fmt.Printf("SNMP contact set to '%s'\n", contact)
			auditLogInfo(fmt.Sprintf("Set SNMP contact: %s", contact))
		}

	case "polling-interval":
		if len(args) < 2 {
			fmt.Println("Usage: set snmp polling-interval <seconds>")
			return
		}
		interval, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Error: Invalid number: %v\n", err)
			return
		}

		if err := snmp.SetPollingInterval(interval); err != nil {
			fmt.Printf("Error: %v\n", err)
			auditLogError(fmt.Sprintf("Failed to set polling interval: %v", err))
		} else {
			fmt.Printf("SNMP polling interval set to %d seconds\n", interval)
			auditLogInfo(fmt.Sprintf("Set SNMP polling interval: %d", interval))
		}

	default:
		fmt.Println("Unknown SNMP command. Use: enable, disable, community, location, contact, polling-interval")
	}
}

func handleSNMPShowCommands(args []string) {
	if len(args) == 0 {
		status, err := snmp.GetSNMPStatus()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(status)
		}
		return
	}

	switch args[0] {
	case "status":
		status, err := snmp.GetSNMPStatus()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(status)
		}

	case "config":
		config, err := snmp.GetSNMPConfig()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(config)
		}

	case "statistics":
		stats, err := snmp.GetStatistics()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println(stats)
		}

	default:
		fmt.Println("Unknown SNMP show command. Use: status, config, statistics")
	}
}
