/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package shell

import (
	"strings"

	"github.com/chzyer/readline"
	"github.com/floof-os/floofos-cli/internal/bird"
	"github.com/floof-os/floofos-cli/internal/vpp"
	"github.com/floof-os/floofos-cli/pkg/detector"
)

type FloofCompleter struct {
	vppClient  *vpp.Client
	birdClient *bird.Client
}

var _ readline.AutoCompleter = (*FloofCompleter)(nil)

func NewFloofCompleter() *FloofCompleter {
	return &FloofCompleter{
		vppClient:  vpp.NewClient(),
		birdClient: bird.NewClient(),
	}
}

func (c *FloofCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	lineStr := string(line[:pos])

	completions := c.getCompletions(lineStr)

	if len(completions) == 0 {
		return [][]rune{}, 0
	}

	completions = uniqueStrings(completions)

	words := strings.Fields(lineStr)
	var prefix string

	if len(words) > 0 && !strings.HasSuffix(lineStr, " ") {
		prefix = words[len(words)-1]
	} else {
		prefix = ""
	}

	if len(completions) == 1 {
		completion := completions[0]

		if prefix == "" || strings.HasPrefix(completion, prefix) {
			suffix := completion[len(prefix):]
			newLine = [][]rune{[]rune(suffix + " ")}
			length = 0
			return newLine, length
		}
		return [][]rune{}, 0
	}

	commonPrefix := findCommonPrefix(completions)

	if len(commonPrefix) > len(prefix) && (prefix == "" || strings.HasPrefix(commonPrefix, prefix)) {
		suffix := commonPrefix[len(prefix):]
		newLine = [][]rune{[]rune(suffix)}
		length = 0
		return newLine, length
	}

	newLine = make([][]rune, len(completions))
	for i, completion := range completions {
		newLine[i] = []rune(completion)
	}

	return newLine, 0
}

func findCommonPrefix(completions []string) string {
	if len(completions) == 0 {
		return ""
	}

	if len(completions) == 1 {
		return completions[0]
	}

	prefix := completions[0]

	for _, comp := range completions[1:] {
		i := 0
		for i < len(prefix) && i < len(comp) && prefix[i] == comp[i] {
			i++
		}
		prefix = prefix[:i]

		if prefix == "" {
			return ""
		}
	}

	return prefix
}

func (c *FloofCompleter) getCompletions(line string) []string {
	if IsOperationalMode() {
		return getOperationalModeCompletions(line, c)
	}

	return getConfigurationModeCompletions(line, c)
}

func getOperationalModeCompletions(line string, c *FloofCompleter) []string {
	words := strings.Fields(line)

	if len(words) == 0 || (len(words) == 1 && !strings.HasSuffix(line, " ")) {
		return []string{"show", "configure", "help", "status", "exit"}
	}

	if words[0] == "show" {
		vppComps, _ := c.vppClient.GetCompletions(line)
		birdComps, _ := c.birdClient.GetCompletions(line)

		allComps := append(vppComps, birdComps...)
		allComps = append(allComps, "configuration", "bgp")
		return uniqueStrings(allComps)
	}

	cmdType := detector.DetectCommandType(line)
	if cmdType == detector.FloofOS {
		return getFloofOSCompletions(line)
	}

	return []string{}
}

func getConfigurationModeCompletions(line string, c *FloofCompleter) []string {
	cmdType := detector.DetectCommandType(line)

	if cmdType == detector.FloofOS {
		return getFloofOSCompletions(line)
	}

	if cmdType == detector.BIRD {
		completions, err := c.birdClient.GetCompletions(line)
		if err == nil && len(completions) > 0 {
			return completions
		}
		return []string{}
	}

	completions, err := c.vppClient.GetCompletions(line)
	if err == nil && len(completions) > 0 {
		return completions
	}

	return []string{}
}

func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

func getFloofOSCompletions(line string) []string {
	words := strings.Fields(line)
	prefix := ""

	if !strings.HasSuffix(line, " ") && len(words) > 0 {
		prefix = words[len(words)-1]
		words = words[:len(words)-1]
	}

	if len(words) == 0 {
		cmds := []string{"commit", "backup", "rollback"}
		return filterCompletions(cmds, prefix)
	}

	firstWord := words[0]

	switch firstWord {
	case "show":
		if len(words) == 1 {
			return filterCompletions([]string{"configuration", "bgp"}, prefix)
		}
	case "set":
		if len(words) == 1 {
			return filterCompletions([]string{"bgp", "hostname"}, prefix)
		}
	case "commit":
		if len(words) == 1 {
			return filterCompletions([]string{"bgp"}, prefix)
		}
	case "backup":
		if len(words) == 1 {
			return filterCompletions([]string{"create", "list", "restore", "delete"}, prefix)
		}
	}

	return []string{}
}

func filterCompletions(completions []string, prefix string) []string {
	if prefix == "" {
		return completions
	}

	var filtered []string
	lowerPrefix := strings.ToLower(prefix)

	for _, completion := range completions {
		if strings.HasPrefix(strings.ToLower(completion), lowerPrefix) {
			filtered = append(filtered, completion)
		}
	}

	return filtered
}
