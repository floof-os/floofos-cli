/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package shell

type ShellMode int

const (
	OperationalMode ShellMode = iota
	ConfigurationMode
)

func (m ShellMode) String() string {
	switch m {
	case OperationalMode:
		return "operational"
	case ConfigurationMode:
		return "configuration"
	default:
		return "unknown"
	}
}

var currentMode = OperationalMode

func GetCurrentMode() ShellMode {
	return currentMode
}

func SetMode(mode ShellMode) {
	currentMode = mode
}

func IsOperationalMode() bool {
	return currentMode == OperationalMode
}

func IsConfigurationMode() bool {
	return currentMode == ConfigurationMode
}
