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
	"fmt"
	"strings"
)

func FormatCompletions(completions []string, termWidth int) string {
	if len(completions) == 0 {
		return ""
	}
	
	maxLen := 0
	for _, comp := range completions {
		if len(comp) > maxLen {
			maxLen = len(comp)
		}
	}
	
	colWidth := maxLen + 4
	if colWidth < 20 {
		colWidth = 20
	}
	
	if termWidth == 0 {
		termWidth = 80
	}
	numCols := termWidth / colWidth
	if numCols < 1 {
		numCols = 1
	}
	if numCols > 6 {
		numCols = 6
	}
	
	var output strings.Builder
	output.WriteString("\n")
	
	for i, comp := range completions {
		output.WriteString(fmt.Sprintf("%-*s", colWidth, comp))
		
		if (i+1)%numCols == 0 {
			output.WriteString("\n")
		}
	}
	
	if len(completions)%numCols != 0 {
		output.WriteString("\n")
	}
	
	return output.String()
}

func FormatVPPStyle(items []string) string {
	return FormatCompletions(items, 80)
}
