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
	"gopkg.in/yaml.v3"
)

type ConfigTemplate struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Type        string                 `yaml:"type"`
	Version     string                 `yaml:"version"`
	Variables   map[string]interface{} `yaml:"variables"`
	Template    string                 `yaml:"template"`
}

type GenerateRequest struct {
	Type      string                 `yaml:"type"`
	Name      string                 `yaml:"name"`
	Variables map[string]interface{} `yaml:"variables"`
	Output    string                 `yaml:"output"`
}

const (
	templatesDir = "/etc/floofos/templates"
	generatedDir = "/etc/floofos/generated"
)

func ExecuteGenerate(args []string, isInteractive bool) error {
	if len(args) == 0 {
		return fmt.Errorf("generate command requires a type (config, template, script, keys)")
	}

	generateType := args[0]
	switch generateType {
	case "config":
		return generateConfig(args[1:], isInteractive)
	case "template":
		return generateTemplate(args[1:], isInteractive)
	case "script":
		return generateScript(args[1:], isInteractive)
	case "keys":
		return generateKeys(args[1:], isInteractive)
	default:
		return fmt.Errorf("unknown generate type: %s", generateType)
	}
}

func generateConfig(args []string, isInteractive bool) error {
	configType := "base"
	if len(args) > 0 {
		configType = args[0]
	}

	if isInteractive {
		color.Cyan("Generating %s Configuration", strings.Title(configType))
		color.Cyan(strings.Repeat("=", 30+len(configType)))
		fmt.Println()
	}

	if err := os.MkdirAll(generatedDir, 0755); err != nil {
		return fmt.Errorf("failed to create generated directory: %w", err)
	}

	switch configType {
	case "base", "basic":
		return generateBaseConfig(isInteractive)
	case "vpp":
		return generateVPPConfig(isInteractive)
	case "bird":
		return generateBIRDConfig(isInteractive)
	case "network":
		return generateNetworkConfig(isInteractive)
	default:
		return fmt.Errorf("unknown config type: %s", configType)
	}
}

func generateTemplate(args []string, isInteractive bool) error {
	templateType := "basic"
	if len(args) > 0 {
		templateType = args[0]
	}

	if isInteractive {
		color.Cyan("Generating %s Template", strings.Title(templateType))
		color.Cyan(strings.Repeat("=", 22+len(templateType)))
		fmt.Println()
	}

	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("failed to create templates directory: %w", err)
	}

	switch templateType {
	case "basic":
		return generateBasicTemplate(isInteractive)
	case "bgp":
		return generateBGPTemplate(isInteractive)
	case "ospf":
		return generateOSPFTemplate(isInteractive)
	case "interface":
		return generateInterfaceTemplate(isInteractive)
	default:
		return fmt.Errorf("unknown template type: %s", templateType)
	}
}

func generateScript(args []string, isInteractive bool) error {
	scriptType := "basic"
	if len(args) > 0 {
		scriptType = args[0]
	}

	if isInteractive {
		color.Cyan("Generating %s Script", strings.Title(scriptType))
		color.Cyan(strings.Repeat("=", 20+len(scriptType)))
		fmt.Println()
	}

	scriptsDir := filepath.Join(generatedDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	switch scriptType {
	case "basic", "startup":
		return generateStartupScript(scriptsDir, isInteractive)
	case "backup":
		return generateBackupScript(scriptsDir, isInteractive)
	case "monitoring":
		return generateMonitoringScript(scriptsDir, isInteractive)
	default:
		return fmt.Errorf("unknown script type: %s", scriptType)
	}
}

func generateKeys(args []string, isInteractive bool) error {
	keyType := "rsa"
	if len(args) > 0 {
		keyType = args[0]
	}

	if isInteractive {
		color.Cyan("Generating %s Keys", strings.ToUpper(keyType))
		color.Cyan(strings.Repeat("=", 16+len(keyType)))
		fmt.Println()
	}

	keysDir := filepath.Join(generatedDir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	switch keyType {
	case "rsa":
		return generateRSAKeys(keysDir, isInteractive)
	case "ecdsa":
		return generateECDSAKeys(keysDir, isInteractive)
	case "ed25519":
		return generateEd25519Keys(keysDir, isInteractive)
	default:
		return fmt.Errorf("unknown key type: %s", keyType)
	}
}

func generateBaseConfig(isInteractive bool) error {
	config := `# FloofOS Base Configuration
# Generated on: %s

# System settings
system:
  hostname: floofos-router
  domain: local
  timezone: UTC

# Network interfaces
interfaces:
  - name: eth0
    type: ethernet
    dhcp: true
  - name: lo
    type: loopback
    address: 127.0.0.1/8

# Routing
routing:
  enabled: true
  protocols:
    - static
    - connected

# Services
services:
  vpp:
    enabled: true
    startup_config: /etc/vpp/startup.conf
  bird:
    enabled: true
    config: /etc/bird/bird.conf

# Logging
logging:
  level: info
  file: /var/log/floofos.log
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	configContent := fmt.Sprintf(config, timestamp)

	outputPath := filepath.Join(generatedDir, "base-config.yaml")
	if err := ioutil.WriteFile(outputPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write base config: %w", err)
	}

	if isInteractive {
		color.Green("✓ Base configuration generated successfully")
		color.White("  Output: %s", outputPath)
	} else {
		fmt.Printf("Base configuration generated: %s\n", outputPath)
	}

	return nil
}

func generateVPPConfig(isInteractive bool) error {
	config := `# VPP Configuration
# Generated on: %s

unix {
  nodaemon
  log /var/log/vpp/vpp.log
  full-coredump
  cli-listen /run/vpp/cli.sock
  gid vpp
  startup-config /etc/vpp/setup.gate
}

api-trace {
  on
}

api-segment {
  gid vpp
}

socksvr {
  default
}

cpu {
  main-core 1
  corelist-workers 2-3
}

buffers {
  buffers-per-numa 128000
}

dpdk {
  dev default {
    num-rx-queues 1
    num-tx-queues 1
  }
  
  # Uncomment and configure for your hardware
  # dev 0000:00:08.0
  # dev 0000:00:09.0
}
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	configContent := fmt.Sprintf(config, timestamp)

	outputPath := filepath.Join(generatedDir, "vpp-startup.conf")
	if err := ioutil.WriteFile(outputPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write VPP config: %w", err)
	}

	if isInteractive {
		color.Green("✓ VPP configuration generated successfully")
		color.White("  Output: %s", outputPath)
		color.Yellow("  Note: Review and customize hardware settings before use")
	} else {
		fmt.Printf("VPP configuration generated: %s\n", outputPath)
	}

	return nil
}

func generateBIRDConfig(isInteractive bool) error {
	config := `# BIRD Configuration
# Generated on: %s

# Router ID - should be unique
router id 192.168.1.1;

# Logging
log syslog all;

# Protocol templates
template bgp ibgp {
  local as 65001;
  next hop self;
  import all;
  export all;
}

template bgp ebgp {
  local as 65001;
  import all;
  export all;
}

# Device protocol
protocol device {
  scan time 10;
}

# Direct protocol
protocol direct {
  interface "*";
}

# Kernel protocol
protocol kernel {
  persist;
  scan time 20;
  import none;
  export all;
}

# Static routes
protocol static {
  # Add static routes here
  # route 10.0.0.0/8 via 192.168.1.254;
}

# BGP protocols
# protocol bgp peer1 from ibgp {
#   neighbor 192.168.1.2 as 65001;
# }
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	configContent := fmt.Sprintf(config, timestamp)

	outputPath := filepath.Join(generatedDir, "bird.conf")
	if err := ioutil.WriteFile(outputPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write BIRD config: %w", err)
	}

	if isInteractive {
		color.Green("✓ BIRD configuration generated successfully")
		color.White("  Output: %s", outputPath)
		color.Yellow("  Note: Customize router ID and protocols before use")
	} else {
		fmt.Printf("BIRD configuration generated: %s\n", outputPath)
	}

	return nil
}

func generateNetworkConfig(isInteractive bool) error {
	config := `# Network Configuration
# Generated on: %s

network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: false
    eth1:
      dhcp4: false
      addresses:
        - 192.168.1.1/24
      gateway4: 192.168.1.254
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	configContent := fmt.Sprintf(config, timestamp)

	outputPath := filepath.Join(generatedDir, "network-config.yaml")
	if err := ioutil.WriteFile(outputPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write network config: %w", err)
	}

	if isInteractive {
		color.Green("✓ Network configuration generated successfully")
		color.White("  Output: %s", outputPath)
	} else {
		fmt.Printf("Network configuration generated: %s\n", outputPath)
	}

	return nil
}

func generateBasicTemplate(isInteractive bool) error {
	tmpl := &ConfigTemplate{
		Name:        "Basic FloofOS Template",
		Description: "Basic configuration template for FloofOS",
		Type:        "system",
		Version:     "1.0",
		Variables: map[string]interface{}{
			"hostname":   "{{.Hostname}}",
			"domain":     "{{.Domain}}",
			"router_id":  "{{.RouterID}}",
			"local_as":   "{{.LocalAS}}",
		},
		Template: `# FloofOS Configuration Template
# Hostname: {{.Hostname}}
# Domain: {{.Domain}}

system:
  hostname: {{.Hostname}}
  domain: {{.Domain}}
  
routing:
  router_id: {{.RouterID}}
  local_as: {{.LocalAS}}
`,
	}

	return saveTemplate("basic.yaml", tmpl, isInteractive)
}

func generateBGPTemplate(isInteractive bool) error {
	tmpl := &ConfigTemplate{
		Name:        "BGP Protocol Template",
		Description: "Template for BGP configuration",
		Type:        "protocol",
		Version:     "1.0",
		Variables: map[string]interface{}{
			"peer_name":    "{{.PeerName}}",
			"peer_ip":      "{{.PeerIP}}",
			"peer_as":      "{{.PeerAS}}",
			"local_as":     "{{.LocalAS}}",
			"description":  "{{.Description}}",
		},
		Template: `# BGP Peer: {{.PeerName}}
protocol bgp {{.PeerName}} {
  description "{{.Description}}";
  local as {{.LocalAS}};
  neighbor {{.PeerIP}} as {{.PeerAS}};
  import all;
  export all;
}
`,
	}

	return saveTemplate("bgp.yaml", tmpl, isInteractive)
}

func generateOSPFTemplate(isInteractive bool) error {
	tmpl := &ConfigTemplate{
		Name:        "OSPF Protocol Template", 
		Description: "Template for OSPF configuration",
		Type:        "protocol",
		Version:     "1.0",
		Variables: map[string]interface{}{
			"area_id":     "{{.AreaID}}",
			"interface":   "{{.Interface}}",
			"cost":        "{{.Cost}}",
			"hello_time":  "{{.HelloTime}}",
		},
		Template: `# OSPF Configuration
protocol ospf {
  area {{.AreaID}} {
    interface "{{.Interface}}" {
      cost {{.Cost}};
      hello {{.HelloTime}};
      dead 40;
      type broadcast;
    };
  };
}
`,
	}

	return saveTemplate("ospf.yaml", tmpl, isInteractive)
}

func generateInterfaceTemplate(isInteractive bool) error {
	tmpl := &ConfigTemplate{
		Name:        "Interface Template",
		Description: "Template for interface configuration",
		Type:        "interface",
		Version:     "1.0", 
		Variables: map[string]interface{}{
			"interface_name": "{{.InterfaceName}}",
			"ip_address":     "{{.IPAddress}}",
			"netmask":        "{{.Netmask}}",
			"mtu":            "{{.MTU}}",
		},
		Template: `# Interface: {{.InterfaceName}}
create loopback interface
set interface ip address {{.InterfaceName}} {{.IPAddress}}/{{.Netmask}}
set interface state {{.InterfaceName}} up
set interface mtu {{.MTU}} {{.InterfaceName}}
`,
	}

	return saveTemplate("interface.yaml", tmpl, isInteractive)
}

func saveTemplate(filename string, tmpl *ConfigTemplate, isInteractive bool) error {
	data, err := yaml.Marshal(tmpl)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	outputPath := filepath.Join(templatesDir, filename)
	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}

	if isInteractive {
		color.Green("✓ Template generated successfully")
		color.White("  Name: %s", tmpl.Name)
		color.White("  Output: %s", outputPath)
	} else {
		fmt.Printf("Template generated: %s\n", outputPath)
	}

	return nil
}

func generateStartupScript(scriptsDir string, isInteractive bool) error {
	script := `#!/bin/bash
# FloofOS Startup Script
# Generated on: %s

set -e

echo "Starting FloofOS services..."

# Start VPP
if systemctl is-enabled vpp >/dev/null 2>&1; then
    echo "Starting VPP..."
    systemctl start vpp
    sleep 2
fi

# Start BIRD
if systemctl is-enabled bird >/dev/null 2>&1; then
    echo "Starting BIRD..."
    systemctl start bird
    sleep 1
fi

# Configure initial interfaces
echo "Configuring interfaces..."
# Add interface configuration commands here

echo "FloofOS startup complete"
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	scriptContent := fmt.Sprintf(script, timestamp)

	outputPath := filepath.Join(scriptsDir, "startup.sh")
	if err := ioutil.WriteFile(outputPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write startup script: %w", err)
	}

	if isInteractive {
		color.Green("✓ Startup script generated successfully")
		color.White("  Output: %s", outputPath)
	}

	return nil
}

func generateBackupScript(scriptsDir string, isInteractive bool) error {
	script := `#!/bin/bash
# FloofOS Backup Script
# Generated on: %s

BACKUP_DIR="/etc/floofos/backups"
DATE=$(date +%%Y-%%m-%%d-%%H%%M%%S)
BACKUP_NAME="auto-backup-$DATE"

echo "Creating backup: $BACKUP_NAME"

# Use floofctl to create backup
/usr/local/bin/floofctl backup create "$BACKUP_NAME"

# Cleanup old backups (keep last 10)
find "$BACKUP_DIR" -maxdepth 1 -type d -name "auto-backup-*" | sort -r | tail -n +11 | xargs rm -rf

echo "Backup complete: $BACKUP_NAME"
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	scriptContent := fmt.Sprintf(script, timestamp)

	outputPath := filepath.Join(scriptsDir, "backup.sh")
	if err := ioutil.WriteFile(outputPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write backup script: %w", err)
	}

	if isInteractive {
		color.Green("✓ Backup script generated successfully")
		color.White("  Output: %s", outputPath)
	}

	return nil
}

func generateMonitoringScript(scriptsDir string, isInteractive bool) error {
	script := `#!/bin/bash
# FloofOS Monitoring Script
# Generated on: %s

LOG_FILE="/var/log/floofos-monitor.log"

log_message() {
    echo "$(date '+%%Y-%%m-%%d %%H:%%M:%%S') - $1" >> "$LOG_FILE"
}

check_service() {
    local service=$1
    if systemctl is-active "$service" >/dev/null 2>&1; then
        log_message "$service is running"
        return 0
    else
        log_message "WARNING: $service is not running"
        return 1
    fi
}

# Check VPP
check_service vpp

# Check BIRD  
check_service bird

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%%' '{print $1}')
MEM_USAGE=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')

log_message "CPU usage: ${CPU_USAGE}%%"
log_message "Memory usage: ${MEM_USAGE}%%"

echo "Monitoring check complete. See $LOG_FILE for details."
`

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	scriptContent := fmt.Sprintf(script, timestamp)

	outputPath := filepath.Join(scriptsDir, "monitor.sh")
	if err := ioutil.WriteFile(outputPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write monitoring script: %w", err)
	}

	if isInteractive {
		color.Green("✓ Monitoring script generated successfully")
		color.White("  Output: %s", outputPath)
	}

	return nil
}

func generateRSAKeys(keysDir string, isInteractive bool) error {
	if isInteractive {
		color.Yellow("Note: This is a simplified key generation example")
		color.Yellow("Use proper cryptographic tools in production")
	}

	privateKey := `-----BEGIN RSA PRIVATE KEY-----
[Generated RSA private key would go here]
Use ssh-keygen or openssl to generate real keys
-----END RSA PRIVATE KEY-----`

	publicKey := `ssh-rsa [Generated RSA public key would go here] floofos@generated`

	privateKeyPath := filepath.Join(keysDir, "id_rsa")
	publicKeyPath := filepath.Join(keysDir, "id_rsa.pub")

	if err := ioutil.WriteFile(privateKeyPath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := ioutil.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	if isInteractive {
		color.Green("✓ RSA key pair generated")
		color.White("  Private key: %s", privateKeyPath)
		color.White("  Public key: %s", publicKeyPath)
		color.Red("  WARNING: These are placeholder keys - generate real keys for production")
	}

	return nil
}

func generateECDSAKeys(keysDir string, isInteractive bool) error {
	if isInteractive {
		color.Yellow("ECDSA key generation not implemented")
		color.Yellow("Use: ssh-keygen -t ecdsa -b 256")
	}
	return fmt.Errorf("ECDSA key generation not implemented")
}

func generateEd25519Keys(keysDir string, isInteractive bool) error {
	if isInteractive {
		color.Yellow("Ed25519 key generation not implemented")
		color.Yellow("Use: ssh-keygen -t ed25519")
	}
	return fmt.Errorf("Ed25519 key generation not implemented")
}
