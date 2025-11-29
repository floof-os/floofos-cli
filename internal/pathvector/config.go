/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package pathvector

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigManager struct {
	client     *Client
	configPath string
	backupDir  string
}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		client:     NewClient(),
		configPath: defaultConfigPath,
		backupDir:  "/etc/pathvector/backups",
	}
}

func (cm *ConfigManager) GenerateBaseConfig(asn int, routerID string, outputPath string) error {
	config, err := cm.client.CreateDefaultConfig(asn, routerID)
	if err != nil {
		return fmt.Errorf("failed to create default config: %w", err)
	}

	if outputPath == "" {
		outputPath = cm.configPath
	}

	configDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (cm *ConfigManager) BackupConfig(backupName string) error {
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", cm.configPath)
	}

	if err := os.MkdirAll(cm.backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	if backupName == "" {
		backupName = fmt.Sprintf("pathvector-backup-%d", os.Getpid())
	}

	backupPath := filepath.Join(cm.backupDir, backupName+".yml")
	
	data, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := ioutil.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

func (cm *ConfigManager) RestoreConfig(backupName string) error {
	backupPath := filepath.Join(cm.backupDir, backupName+".yml")
	
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	data, err := ioutil.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var config PathvectorConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid backup file: %w", err)
	}

	if err := cm.BackupConfig("pre-restore"); err != nil {
		return fmt.Errorf("failed to backup current config: %w", err)
	}

	if err := ioutil.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to restore config file: %w", err)
	}

	return nil
}

func (cm *ConfigManager) ValidateConfigFile(configPath string) error {
	if configPath == "" {
		configPath = cm.configPath
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config PathvectorConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid YAML format: %w", err)
	}

	if config.ASN == 0 {
		return fmt.Errorf("ASN must be specified")
	}

	if config.RouterID == "" {
		return fmt.Errorf("router-id must be specified")
	}

	if config.ASN < 1 || config.ASN > 4294967295 {
		return fmt.Errorf("invalid ASN: %d (must be 1-4294967295)", config.ASN)
	}

	parts := strings.Split(config.RouterID, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid router-id format: %s (should be IPv4 address)", config.RouterID)
	}

	for _, part := range parts {
		if val, err := strconv.Atoi(part); err != nil || val < 0 || val > 255 {
			return fmt.Errorf("invalid router-id format: %s", config.RouterID)
		}
	}

	peerNames := make(map[string]bool)
	for i, peer := range config.Peers {
		if peer.Name == "" {
			return fmt.Errorf("peer %d: name is required", i)
		}

		if peerNames[peer.Name] {
			return fmt.Errorf("duplicate peer name: %s", peer.Name)
		}
		peerNames[peer.Name] = true

		if peer.ASN == 0 {
			return fmt.Errorf("peer %s: ASN is required", peer.Name)
		}

		if peer.Address == "" {
			return fmt.Errorf("peer %s: address is required", peer.Name)
		}

		if peer.Type != "" {
			validTypes := []string{"upstream", "peer", "downstream", "customer"}
			validType := false
			for _, vt := range validTypes {
				if peer.Type == vt {
					validType = true
					break
				}
			}
			if !validType {
				return fmt.Errorf("peer %s: invalid type %s (must be one of: %s)", 
					peer.Name, peer.Type, strings.Join(validTypes, ", "))
			}
		}
	}

	return nil
}

func (cm *ConfigManager) GetConfigSummary() (map[string]interface{}, error) {
	config, err := cm.client.LoadConfig()
	if err != nil {
		return nil, err
	}

	summary := map[string]interface{}{
		"asn":          config.ASN,
		"router_id":    config.RouterID,
		"peer_count":   len(config.Peers),
		"prefix_count": len(config.Prefixes),
	}

	peerTypes := make(map[string]int)
	for _, peer := range config.Peers {
		if peer.Type == "" {
			peerTypes["unspecified"]++
		} else {
			peerTypes[peer.Type]++
		}
	}
	summary["peers_by_type"] = peerTypes

	templates := make([]string, 0, len(config.Templates))
	for name := range config.Templates {
		templates = append(templates, name)
	}
	summary["templates"] = templates

	return summary, nil
}

func (cm *ConfigManager) ListBackups() ([]string, error) {
	if _, err := os.Stat(cm.backupDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	files, err := ioutil.ReadDir(cm.backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yml") {
			backupName := strings.TrimSuffix(file.Name(), ".yml")
			backups = append(backups, backupName)
		}
	}

	return backups, nil
}

func (cm *ConfigManager) ImportConfig(sourcePath string) error {
	if err := cm.ValidateConfigFile(sourcePath); err != nil {
		return fmt.Errorf("source config validation failed: %w", err)
	}

	data, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source config: %w", err)
	}

	if err := cm.BackupConfig("pre-import"); err != nil {
		return fmt.Errorf("failed to backup current config: %w", err)
	}

	if err := ioutil.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write imported config: %w", err)
	}

	return nil
}

func (cm *ConfigManager) ExportConfig(targetPath string) error {
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", cm.configPath)
	}

	data, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	if err := ioutil.WriteFile(targetPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write exported config: %w", err)
	}

	return nil
}

func (cm *ConfigManager) MergeConfigs(configPaths []string, outputPath string) error {
	if len(configPaths) == 0 {
		return fmt.Errorf("no config files specified")
	}

	var mergedConfig PathvectorConfig
	peerNames := make(map[string]bool)

	for i, configPath := range configPaths {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		var config PathvectorConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config file %s: %w", configPath, err)
		}

		if i == 0 {
			mergedConfig = config
		} else {
			if config.ASN != 0 && config.ASN != mergedConfig.ASN {
				return fmt.Errorf("ASN mismatch: %d vs %d", config.ASN, mergedConfig.ASN)
			}

			if config.RouterID != "" && config.RouterID != mergedConfig.RouterID {
				return fmt.Errorf("router-id mismatch: %s vs %s", config.RouterID, mergedConfig.RouterID)
			}

			for _, peer := range config.Peers {
				if peerNames[peer.Name] {
					return fmt.Errorf("duplicate peer name: %s", peer.Name)
				}
				peerNames[peer.Name] = true
				mergedConfig.Peers = append(mergedConfig.Peers, peer)
			}

			mergedConfig.Prefixes = append(mergedConfig.Prefixes, config.Prefixes...)

			if mergedConfig.Templates == nil {
				mergedConfig.Templates = make(map[string]interface{})
			}
			for name, template := range config.Templates {
				mergedConfig.Templates[name] = template
			}

			if mergedConfig.Filters == nil {
				mergedConfig.Filters = make(map[string]interface{})
			}
			for name, filter := range config.Filters {
				mergedConfig.Filters[name] = filter
			}

			if mergedConfig.Communities == nil {
				mergedConfig.Communities = make(map[string]interface{})
			}
			for name, community := range config.Communities {
				mergedConfig.Communities[name] = community
			}
		}
	}

	for i := range mergedConfig.Peers {
		peerNames[mergedConfig.Peers[i].Name] = true
	}

	data, err := yaml.Marshal(&mergedConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal merged config: %w", err)
	}

	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write merged config: %w", err)
	}

	return nil
}
