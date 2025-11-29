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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	VPPcfgVenvPath   = "/root/vppcfg/.venv/bin/vppcfg"
	DataplaneYAML    = "/etc/vpp/dataplane.yaml"
	VPPcfgOutput     = "/etc/vpp/config/vppcfg.vpp"
	
	HeadVPP          = "/etc/vpp/config/head.vpp"
	TailVPP          = "/etc/vpp/config/tail.vpp"
	
	BackupDir        = "/etc/floofos/backups/vppcfg"
)

var (
	successColor = color.New(color.FgGreen, color.Bold)
	errorColor   = color.New(color.FgRed, color.Bold)
	infoColor    = color.New(color.FgCyan)
)

func VPPcfgCommit() error {
	infoColor.Println("% Committing configuration...")
	
	if err := vppcfgWrite(); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	
	if err := vppcfgCheck(); err != nil {
		return fmt.Errorf("check failed: %w", err)
	}
	
	if err := vppcfgPlan(); err != nil {
		return fmt.Errorf("plan failed: %w", err)
	}
	
	successColor.Println("% Configuration complete")
	return nil
}

func vppcfgWrite() error {
	cmd := exec.Command(VPPcfgVenvPath, "dump", "-o", DataplaneYAML)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vppcfg dump error: %v\n%s", err, stderr.String())
	}
	
	return nil
}

func vppcfgCheck() error {
	cmd := exec.Command(VPPcfgVenvPath, "check", "-c", DataplaneYAML)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("configuration validation failed:\n%s", stderr.String())
	}
	
	return nil
}

func vppcfgPlan() error {
	cmd := exec.Command(VPPcfgVenvPath, "plan", "--novpp", "-c", DataplaneYAML, "-o", VPPcfgOutput)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vppcfg plan error: %v\n%s", err, stderr.String())
	}
	
	return nil
}

func ShowConfiguration(format string) error {
	if err := showConfigContent(HeadVPP); err != nil {
		return err
	}
	
	if err := showConfigContent(VPPcfgOutput); err != nil {
		return err
	}
	
	if err := showConfigContent(TailVPP); err != nil {
		return err
	}
	
	if err := showConfigContent("/etc/pathvector.yml"); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	
	return nil
}

func showConfigContent(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Println(line)
	}
	
	return nil
}

func getLastModified() string {
	files := []string{HeadVPP, VPPcfgOutput, TailVPP}
	var latest time.Time
	
	for _, file := range files {
		if info, err := os.Stat(file); err == nil {
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
	}
	
	if latest.IsZero() {
		return "unknown"
	}
	
	return latest.Format("2006-01-02 15:04:05")
}

func CreateBackup(comment string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("backup-%s", timestamp)
	if comment != "" {
		comment = strings.ReplaceAll(comment, " ", "-")
		comment = strings.ReplaceAll(comment, "/", "-")
		backupName = fmt.Sprintf("backup-%s-%s", timestamp, comment)
	}
	
	backupPath := filepath.Join(BackupDir, backupName)
	
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return "", fmt.Errorf("cannot create backup directory: %w", err)
	}
	
	filesToBackup := map[string]string{
		HeadVPP:       "head.vpp",
		VPPcfgOutput:  "vppcfg.vpp",
		TailVPP:       "tail.vpp",
		DataplaneYAML: "dataplane.yaml",
	}
	
	for src, dst := range filesToBackup {
		if err := copyFile(src, filepath.Join(backupPath, dst)); err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("backup failed for %s: %w", src, err)
			}
		}
	}
	
	successColor.Printf("% Backup created: %s\n", backupName)
	return backupName, nil
}

func Rollback(backupName string) error {
	var backupPath string
	
	if backupName == "" {
		recent, err := getMostRecentBackup()
		if err != nil {
			return err
		}
		backupPath = recent
		backupName = filepath.Base(recent)
	} else {
		backupPath = filepath.Join(BackupDir, backupName)
	}
	
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupName)
	}
	
	infoColor.Printf("% Rolling back to: %s\n", backupName)
	
	filesToRestore := map[string]string{
		"head.vpp":       HeadVPP,
		"vppcfg.vpp":     VPPcfgOutput,
		"tail.vpp":       TailVPP,
		"dataplane.yaml": DataplaneYAML,
	}
	
	for src, dst := range filesToRestore {
		srcPath := filepath.Join(backupPath, src)
		if err := copyFile(srcPath, dst); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("rollback failed for %s: %w", src, err)
			}
		}
	}
	
	successColor.Println("% Rollback complete")
	infoColor.Println("% Note: Run 'commit' to apply the restored configuration to VPP")
	
	return nil
}

func ListBackups() error {
	if _, err := os.Stat(BackupDir); os.IsNotExist(err) {
		infoColor.Println("% No backups found")
		return nil
	}
	
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return fmt.Errorf("cannot read backup directory: %w", err)
	}
	
	if len(entries) == 0 {
		infoColor.Println("% No backups found")
		return nil
	}
	
	fmt.Println()
	color.New(color.FgYellow, color.Bold).Println("Available Backups:")
	fmt.Println(strings.Repeat("-", 70))
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		info, err := entry.Info()
		if err != nil {
			continue
		}
		
		fmt.Printf("  %-40s  %s\n", 
			entry.Name(), 
			info.ModTime().Format("2006-01-02 15:04:05"))
	}
	
	fmt.Println()
	return nil
}

func getMostRecentBackup() (string, error) {
	if _, err := os.Stat(BackupDir); os.IsNotExist(err) {
		return "", fmt.Errorf("no backups found")
	}
	
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return "", fmt.Errorf("cannot read backup directory: %w", err)
	}
	
	var mostRecent string
	var mostRecentTime time.Time
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		info, err := entry.Info()
		if err != nil {
			continue
		}
		
		if info.ModTime().After(mostRecentTime) {
			mostRecentTime = info.ModTime()
			mostRecent = filepath.Join(BackupDir, entry.Name())
		}
	}
	
	if mostRecent == "" {
		return "", fmt.Errorf("no backups found")
	}
	
	return mostRecent, nil
}
