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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Client struct {
	baseURL    string
	apiKey     string
	timeout    time.Duration
	configPath string
}

type PathvectorConfig struct {
	ASN         int                    `yaml:"asn"`
	RouterID    string                 `yaml:"router-id"`
	Prefixes    []string               `yaml:"prefixes"`
	Peers       []PeerConfig           `yaml:"peers"`
	Templates   map[string]interface{} `yaml:"templates"`
	Filters     map[string]interface{} `yaml:"filters"`
	Communities map[string]interface{} `yaml:"communities"`
}

type PeerConfig struct {
	Name        string   `yaml:"name"`
	ASN         int      `yaml:"asn"`
	Address     string   `yaml:"address"`
	Type        string   `yaml:"type"`
	Templates   []string `yaml:"templates,omitempty"`
	Import      string   `yaml:"import,omitempty"`
	Export      string   `yaml:"export,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

const (
	defaultConfigPath = "/etc/pathvector/pathvector.yml"
	defaultTimeout    = 30 * time.Second
)

func NewClient() *Client {
	return &Client{
		baseURL:    "http://localhost:8080",
		timeout:    defaultTimeout,
		configPath: defaultConfigPath,
	}
}

func NewClientWithConfig(baseURL, apiKey, configPath string) *Client {
	return &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		timeout:    defaultTimeout,
		configPath: configPath,
	}
}

func (c *Client) LoadConfig() (*PathvectorConfig, error) {
	if _, err := os.Stat(c.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("pathvector config file not found: %s", c.configPath)
	}

	data, err := ioutil.ReadFile(c.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PathvectorConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (c *Client) SaveConfig(config *PathvectorConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configDir := filepath.Dir(c.configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := ioutil.WriteFile(c.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (c *Client) GetStatus() (map[string]interface{}, error) {
	resp, err := c.makeRequest("GET", "/api/status", nil)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("API error: %s", resp.Error)
	}

	if data, ok := resp.Data.(map[string]interface{}); ok {
		return data, nil
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (c *Client) GetPeers() ([]map[string]interface{}, error) {
	resp, err := c.makeRequest("GET", "/api/peers", nil)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("API error: %s", resp.Error)
	}

	if data, ok := resp.Data.([]interface{}); ok {
		var peers []map[string]interface{}
		for _, item := range data {
			if peer, ok := item.(map[string]interface{}); ok {
				peers = append(peers, peer)
			}
		}
		return peers, nil
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (c *Client) GetRoutes() (map[string]interface{}, error) {
	resp, err := c.makeRequest("GET", "/api/routes", nil)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("API error: %s", resp.Error)
	}

	if data, ok := resp.Data.(map[string]interface{}); ok {
		return data, nil
	}

	return nil, fmt.Errorf("unexpected response format")
}

func (c *Client) ReloadConfig() error {
	resp, err := c.makeRequest("POST", "/api/reload", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("API error: %s", resp.Error)
	}

	return nil
}

func (c *Client) GenerateConfig() error {
	resp, err := c.makeRequest("POST", "/api/generate", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("API error: %s", resp.Error)
	}

	return nil
}

func (c *Client) IsAvailable() bool {
	_, err := c.GetStatus()
	return err == nil
}

func (c *Client) ValidateConfig() error {
	config, err := c.LoadConfig()
	if err != nil {
		return err
	}

	if config.ASN == 0 {
		return fmt.Errorf("ASN must be specified")
	}

	if config.RouterID == "" {
		return fmt.Errorf("router-id must be specified")
	}

	for i, peer := range config.Peers {
		if peer.Name == "" {
			return fmt.Errorf("peer %d: name is required", i)
		}
		if peer.ASN == 0 {
			return fmt.Errorf("peer %s: ASN is required", peer.Name)
		}
		if peer.Address == "" {
			return fmt.Errorf("peer %s: address is required", peer.Name)
		}
	}

	return nil
}

func (c *Client) CreateDefaultConfig(asn int, routerID string) (*PathvectorConfig, error) {
	config := &PathvectorConfig{
		ASN:      asn,
		RouterID: routerID,
		Prefixes: []string{},
		Peers:    []PeerConfig{},
		Templates: map[string]interface{}{
			"upstream": map[string]interface{}{
				"allow-blackhole-community": true,
				"announce-default":          false,
				"local-pref":                100,
			},
			"peer": map[string]interface{}{
				"allow-blackhole-community": true,
				"announce-default":          false,
				"local-pref":                200,
			},
			"downstream": map[string]interface{}{
				"allow-blackhole-community": false,
				"announce-default":          true,
				"local-pref":                300,
			},
		},
		Filters: map[string]interface{}{
			"bogons": []string{
				"0.0.0.0/8",
				"10.0.0.0/8",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"172.16.0.0/12",
				"192.0.2.0/24",
				"192.168.0.0/16",
				"224.0.0.0/4",
				"240.0.0.0/4",
			},
		},
		Communities: map[string]interface{}{
			"blackhole": fmt.Sprintf("%d:666", asn),
			"upstream":  fmt.Sprintf("%d:100", asn),
			"peer":      fmt.Sprintf("%d:200", asn),
			"customer":  fmt.Sprintf("%d:300", asn),
		},
	}

	return config, nil
}

func (c *Client) AddPeer(peer PeerConfig) error {
	config, err := c.LoadConfig()
	if err != nil {
		return err
	}

	for _, existingPeer := range config.Peers {
		if existingPeer.Name == peer.Name {
			return fmt.Errorf("peer %s already exists", peer.Name)
		}
	}

	config.Peers = append(config.Peers, peer)
	return c.SaveConfig(config)
}

func (c *Client) RemovePeer(peerName string) error {
	config, err := c.LoadConfig()
	if err != nil {
		return err
	}

	var newPeers []PeerConfig
	found := false
	for _, peer := range config.Peers {
		if peer.Name != peerName {
			newPeers = append(newPeers, peer)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("peer %s not found", peerName)
	}

	config.Peers = newPeers
	return c.SaveConfig(config)
}

func (c *Client) UpdatePeer(peerName string, updates PeerConfig) error {
	config, err := c.LoadConfig()
	if err != nil {
		return err
	}

	found := false
	for i, peer := range config.Peers {
		if peer.Name == peerName {
			if updates.ASN != 0 {
				config.Peers[i].ASN = updates.ASN
			}
			if updates.Address != "" {
				config.Peers[i].Address = updates.Address
			}
			if updates.Type != "" {
				config.Peers[i].Type = updates.Type
			}
			if updates.Description != "" {
				config.Peers[i].Description = updates.Description
			}
			if len(updates.Templates) > 0 {
				config.Peers[i].Templates = updates.Templates
			}
			if updates.Import != "" {
				config.Peers[i].Import = updates.Import
			}
			if updates.Export != "" {
				config.Peers[i].Export = updates.Export
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("peer %s not found", peerName)
	}

	return c.SaveConfig(config)
}

func (c *Client) makeRequest(method, path string, body interface{}) (*APIResponse, error) {
	url := c.baseURL + path

	var bodyReader *strings.Reader
	if body != nil {
		bodyData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = strings.NewReader(string(bodyData))
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, url, bodyReader)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respData, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &apiResp, nil
}
