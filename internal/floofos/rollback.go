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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

func ExecuteRollback(args []string, isInteractive bool) error {
	if len(args) == 0 {
		return fmt.Errorf("rollback command requires an action (to, list, info)")
	}

	action := args[0]
	switch action {
	case "to":
		if len(args) < 2 {
			return fmt.Errorf("rollback to requires backup ID or name")
		}
		return rollbackTo(args[1], isInteractive)
	case "list":
		return listRollbackTargets(isInteractive)
	case "info":
		if len(args) < 2 {
			return fmt.Errorf("rollback info requires backup ID or name")
		}
		return showRollbackInfo(args[1], isInteractive)
	default:
		return fmt.Errorf("unknown rollback action: %s", action)
	}
}

func rollbackTo(idOrName string, isInteractive bool) error {
	backup, err := findBackup(idOrName)
	if err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}

	if isInteractive {
		color.Cyan("Rolling back to backup: %s", backup.Name)
		color.Cyan(strings.Repeat("=", 25+len(backup.Name)))
		fmt.Println()

		color.White("Backup Information:")
		color.White("  ID: %s", backup.ID)
		color.White("  Name: %s", backup.Name)
		color.White("  Date: %s", backup.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Println()

		color.Yellow("WARNING: This will replace current configurations!")
		fmt.Println()
	}

	currentBackupName := fmt.Sprintf("pre-rollback-%s", time.Now().Format("20060102-150405"))
	if err := createBackup(currentBackupName, false); err != nil {
		if isInteractive {
			color.Yellow("Warning: Failed to create pre-rollback backup: %v", err)
		}
	} else {
		if isInteractive {
			color.Green("✓ Created pre-rollback backup: %s", currentBackupName)
		}
	}

	backupPath := filepath.Join(backupDir, backup.ID)

	if err := restoreVPPConfig(backupPath, isInteractive); err != nil {
		if isInteractive {
			color.Red("✗ Failed to restore VPP config: %v", err)
		}
	} else {
		if isInteractive {
			color.Green("✓ VPP configuration restored")
		}
	}

	if err := restoreBIRDConfig(backupPath, isInteractive); err != nil {
		if isInteractive {
			color.Red("✗ Failed to restore BIRD config: %v", err)
		}
	} else {
		if isInteractive {
			color.Green("✓ BIRD configuration restored")
		}
	}

	if err := restoreFloofOSConfig(backupPath, isInteractive); err != nil {
		if isInteractive {
			color.Red("✗ Failed to restore FloofOS config: %v", err)
		}
	} else {
		if isInteractive {
			color.Green("✓ FloofOS configuration restored")
		}
	}

	if isInteractive {
		fmt.Println()
		color.Green("✓ Rollback completed successfully")
		color.Yellow("Note: You may need to restart services for changes to take effect")
		color.White("Restart commands:")
		color.White("  sudo systemctl restart vpp")
		color.White("  sudo systemctl restart bird")
	} else {
		fmt.Printf("Rollback completed: %s -> %s\n", backup.ID, backup.Name)
	}

	return nil
}

func listRollbackTargets(isInteractive bool) error {
	return listBackups(isInteractive)
}

func showRollbackInfo(idOrName string, isInteractive bool) error {
	backup, err := findBackup(idOrName)
	if err != nil {
		return fmt.Errorf("rollback target not found: %w", err)
	}

	backupPath := filepath.Join(backupDir, backup.ID)

	if isInteractive {
		color.Cyan("Rollback Target Information")
		color.Cyan("===========================")
		fmt.Println()

		color.Green("Target Details:")
		color.White("  ID: %s", backup.ID)
		color.White("  Name: %s", backup.Name)
		color.White("  Date: %s", backup.Timestamp.Format("2006-01-02 15:04:05"))
		color.White("  Description: %s", backup.Description)
		fmt.Println()

		color.Green("Will restore:")

		vppFiles := []string{"dataplane.yaml", "head.vpp", "vppcfg.vpp", "tail.vpp"}
		for _, vppFile := range vppFiles {
			vppBackupPath := filepath.Join(backupPath, vppFile)
			if _, err := os.Stat(vppBackupPath); err == nil {
				color.White("  ✓ VPP %s", vppFile)
			} else {
				color.New(color.FgHiBlack).Printf("  - VPP %s (not available)\n", vppFile)
			}
		}

		pathvectorBackupPath := filepath.Join(backupPath, "pathvector.yml")
		if _, err := os.Stat(pathvectorBackupPath); err == nil {
			color.White("  ✓ Pathvector configuration (BGP)")
		} else {
			color.New(color.FgHiBlack).Println("  - Pathvector configuration (not available)")
		}

		floofBackupPath := filepath.Join(backupPath, "floofos")
		if _, err := os.Stat(floofBackupPath); err == nil {
			color.White("  ✓ FloofOS configuration (%s)", configDir)
		} else {
			color.New(color.FgHiBlack).Println("  - FloofOS configuration (not available)")
		}

		fmt.Println()
		color.Yellow("To perform rollback, use: rollback to %s", backup.ID)
	} else {
		fmt.Printf("Rollback Target: %s (%s)\n", backup.ID, backup.Name)
		fmt.Printf("Date: %s\n", backup.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("Description: %s\n", backup.Description)
	}

	return nil
}

func restoreVPPConfig(backupPath string, isInteractive bool) error {
	vppFiles := map[string]string{
		"dataplane.yaml": vppDataplaneYaml,
		"head.vpp":       vppHeadVpp,
		"vppcfg.vpp":     vppVppcfgVpp,
		"tail.vpp":       vppTailVpp,
	}

	for backupName, dstPath := range vppFiles {
		srcPath := filepath.Join(backupPath, backupName)

		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			if isInteractive {
				color.Yellow("%s backup not found, skipping", backupName)
			}
			continue
		}

		if _, err := os.Stat(dstPath); err == nil {
			currentBackup := dstPath + ".pre-rollback"
			if err := copyFile(dstPath, currentBackup); err != nil {
				if isInteractive {
					color.Yellow("Warning: Failed to backup current %s: %v", backupName, err)
				}
			}
		}

		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to restore %s: %w", backupName, err)
		}
	}

	return nil
}

func restoreBIRDConfig(backupPath string, isInteractive bool) error {
	srcPath := filepath.Join(backupPath, "pathvector.yml")

	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		if isInteractive {
			color.Yellow("pathvector.yml backup not found, skipping")
		}
		return nil
	}

	if _, err := os.Stat(pathvectorYml); err == nil {
		currentBackup := pathvectorYml + ".pre-rollback"
		if err := copyFile(pathvectorYml, currentBackup); err != nil {
			if isInteractive {
				color.Yellow("Warning: Failed to backup current pathvector.yml: %v", err)
			}
		}
	}

	if err := copyFile(srcPath, pathvectorYml); err != nil {
		return fmt.Errorf("failed to restore pathvector.yml: %w", err)
	}

	return nil
}

func restoreFloofOSConfig(backupPath string, isInteractive bool) error {
	floofBackupPath := filepath.Join(backupPath, "floofos")

	if _, err := os.Stat(floofBackupPath); os.IsNotExist(err) {
		if isInteractive {
			color.Yellow("FloofOS configuration backup not found, skipping")
		}
		return nil
	}

	if _, err := os.Stat(configDir); err == nil {
		currentBackup := configDir + ".pre-rollback"
		if err := os.RemoveAll(currentBackup); err != nil {
			if isInteractive {
				color.Yellow("Warning: Failed to remove old backup: %v", err)
			}
		}
		if err := copyDir(configDir, currentBackup); err != nil {
			if isInteractive {
				color.Yellow("Warning: Failed to backup current FloofOS config: %v", err)
			}
		}
	}

	if err := os.RemoveAll(configDir); err != nil {
		return fmt.Errorf("failed to remove current FloofOS config: %w", err)
	}

	if err := copyDir(floofBackupPath, configDir); err != nil {
		return fmt.Errorf("failed to restore FloofOS config: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}

	return ioutil.WriteFile(dst, data, 0644)
}
