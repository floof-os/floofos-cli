/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package floofos

import (
	"github.com/floof-os/floofos-cli/internal/pathvector"
)

func SetBGP() error {
	return pathvector.SetBGP()
}

func CommitBGP() error {
	return pathvector.CommitBGP()
}

func ShowBGPSummary() error {
	return pathvector.ShowBGPSummary()
}

func ShowBGPConfig() error {
	return pathvector.ShowBGPConfig()
}
