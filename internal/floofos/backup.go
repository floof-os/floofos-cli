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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

type BackupInfo struct {
	ID          string    `json:"id" yaml:"id"`
	Name        string    `json:"name" yaml:"name"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	Description string    `json:"description" yaml:"description"`
	Size        int64     `json:"size" yaml:"size"`
	ConfigPath  string    `json:"config_path" yaml:"config_path"`
	VPPConfig   string    `json:"vpp_config" yaml:"vpp_config"`
	BIRDConfig  string    `json:"bird_config" yaml:"bird_config"`
}

func ExecuteBackup(args []string, isInteractive bool) error {
	if len(args) == 0 {
		return fmt.Errorf("backup command requires an action (create, list, delete, info)")
	}

	action := args[0]
	switch action {
	case "create":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		return createBackup(name, isInteractive)
	case "list":
		return listBackups(isInteractive)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("delete requires backup ID or name")
		}
		return deleteBackup(args[1], isInteractive)
	case "info":
		if len(args) < 2 {
			return fmt.Errorf("info requires backup ID or name")
		}
		return showBackupInfo(args[1], isInteractive)
	default:
		return fmt.Errorf("unknown backup action: %s", action)
	}
}

func createBackup(name string, isInteractive bool) error {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now()
	backupID := timestamp.Format("2006-01-02-150405")
	if name == "" {
		name = "backup-" + backupID
	}

	backup := &BackupInfo{
		ID:          backupID,
		Name:        name,
		Timestamp:   timestamp,
		Description: fmt.Sprintf("Automatic backup created on %s", timestamp.Format("2006-01-02 15:04:05")),
	}

	backupPath := filepath.Join(backupDir, backupID)
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup path: %w", err)
	}

	if err := backupVPPConfig(backupPath, backup); err != nil {
		if isInteractive {
			color.Yellow("Warning: Failed to backup VPP config: %v", err)
		}
	}

	if err := backupBIRDConfig(backupPath, backup); err != nil {
		if isInteractive {
			color.Yellow("Warning: Failed to backup BIRD config: %v", err)
		}
	}

	if err := backupFloofOSConfig(backupPath, backup); err != nil {
		if isInteractive {
			color.Yellow("Warning: Failed to backup FloofOS config: %v", err)
		}
	}

	metadataPath := filepath.Join(backupPath, "metadata.json")
	metadataData, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup metadata: %w", err)
	}

	if err := ioutil.WriteFile(metadataPath, metadataData, 0644); err != nil {
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}

	if isInteractive {
		color.Green("✓ Backup created successfully")
		color.White("  ID: %s", backup.ID)
		color.White("  Name: %s", backup.Name)
		color.White("  Path: %s", backupPath)
	} else {
		fmt.Printf("Backup created: %s (%s)\n", backup.ID, backup.Name)
	}

	return nil
}

func listBackups(isInteractive bool) error {
	backups, err := getAvailableBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	if len(backups) == 0 {
		if isInteractive {
			color.Yellow("No backups found")
		} else {
			fmt.Println("No backups found")
		}
		return nil
	}

	if isInteractive {
		color.Cyan("Available Backups")
		color.Cyan("=================")
		fmt.Println()

		for _, backup := range backups {
			color.Green("ID: %s", backup.ID)
			color.White("  Name: %s", backup.Name)
			color.White("  Date: %s", backup.Timestamp.Format("2006-01-02 15:04:05"))
			color.White("  Description: %s", backup.Description)
			fmt.Println()
		}
	} else {
		for _, backup := range backups {
			fmt.Printf("%s\t%s\t%s\t%s\n",
				backup.ID,
				backup.Name,
				backup.Timestamp.Format("2006-01-02 15:04:05"),
				backup.Description)
		}
	}

	return nil
}

func deleteBackup(idOrName string, isInteractive bool) error {
	backup, err := findBackup(idOrName)
	if err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}

	backupPath := filepath.Join(backupDir, backup.ID)
	if err := os.RemoveAll(backupPath); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}

	if isInteractive {
		color.Green("✓ Backup deleted successfully")
		color.White("  ID: %s", backup.ID)
		color.White("  Name: %s", backup.Name)
	} else {
		fmt.Printf("Backup deleted: %s (%s)\n", backup.ID, backup.Name)
	}

	return nil
}

func showBackupInfo(idOrName string, isInteractive bool) error {
	backup, err := findBackup(idOrName)
	if err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}

	backupPath := filepath.Join(backupDir, backup.ID)

	if isInteractive {
		color.Cyan("Backup Information")
		color.Cyan("==================")
		fmt.Println()

		color.Green("Basic Info:")
		color.White("  ID: %s", backup.ID)
		color.White("  Name: %s", backup.Name)
		color.White("  Date: %s", backup.Timestamp.Format("2006-01-02 15:04:05"))
		color.White("  Description: %s", backup.Description)
		color.White("  Path: %s", backupPath)
		fmt.Println()

		if info, err := os.Stat(backupPath); err == nil {
			if info.IsDir() {
				if size, err := getDirSize(backupPath); err == nil {
					color.White("  Size: %d bytes", size)
				}
			}
		}

		color.Green("Contents:")
		if files, err := ioutil.ReadDir(backupPath); err == nil {
			for _, file := range files {
				color.White("  - %s (%d bytes)", file.Name(), file.Size())
			}
		}
	} else {
		fmt.Printf("ID: %s\n", backup.ID)
		fmt.Printf("Name: %s\n", backup.Name)
		fmt.Printf("Date: %s\n", backup.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("Description: %s\n", backup.Description)
		fmt.Printf("Path: %s\n", backupPath)
	}

	return nil
}

func backupVPPConfig(backupPath string, backup *BackupInfo) error {
	vppFiles := map[string]string{
		"dataplane.yaml": vppDataplaneYaml,
		"head.vpp":       vppHeadVpp,
		"vppcfg.vpp":     vppVppcfgVpp,
		"tail.vpp":       vppTailVpp,
	}

	for backupName, srcPath := range vppFiles {
		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			continue
		}

		data, err := ioutil.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", srcPath, err)
		}

		dstPath := filepath.Join(backupPath, backupName)
		if err := ioutil.WriteFile(dstPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", backupName, err)
		}
	}

	backup.VPPConfig = backupPath
	return nil
}

func backupBIRDConfig(backupPath string, backup *BackupInfo) error {
	if _, err := os.Stat(pathvectorYml); os.IsNotExist(err) {
		return nil
	}

	data, err := ioutil.ReadFile(pathvectorYml)
	if err != nil {
		return fmt.Errorf("failed to read pathvector.yml: %w", err)
	}

	dstPath := filepath.Join(backupPath, "pathvector.yml")
	if err := ioutil.WriteFile(dstPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write pathvector.yml: %w", err)
	}

	backup.BIRDConfig = backupPath
	return nil
}

func backupFloofOSConfig(backupPath string, backup *BackupInfo) error {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return nil
	}

	floofConfigBackup := filepath.Join(backupPath, "floofos")
	if err := copyDir(configDir, floofConfigBackup); err != nil {
		return err
	}

	backup.ConfigPath = floofConfigBackup
	return nil
}

func getAvailableBackups() ([]*BackupInfo, error) {
	var backups []*BackupInfo

	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return backups, nil
	}

	entries, err := ioutil.ReadDir(backupDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metadataPath := filepath.Join(backupDir, entry.Name(), "metadata.json")
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			continue
		}

		data, err := ioutil.ReadFile(metadataPath)
		if err != nil {
			continue
		}

		var backup BackupInfo
		if err := json.Unmarshal(data, &backup); err != nil {
			continue
		}

		backups = append(backups, &backup)
	}

	return backups, nil
}

func findBackup(idOrName string) (*BackupInfo, error) {
	backups, err := getAvailableBackups()
	if err != nil {
		return nil, err
	}

	for _, backup := range backups {
		if backup.ID == idOrName || backup.Name == idOrName {
			return backup, nil
		}
	}

	return nil, fmt.Errorf("backup not found: %s", idOrName)
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			data, err := ioutil.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if err := ioutil.WriteFile(dstPath, data, entry.Mode()); err != nil {
				return err
			}
		}
	}

	return nil
}
