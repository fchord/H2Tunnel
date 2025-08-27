package main

import (
	"flag"
	"log"	
	"os"
	"encoding/json"
	"fmt"
	"net"
	"time"
	"bytes"
	"strconv"
	"encoding/binary"

	"H2Tunnel/rsa_demo"
)

type CmdType uint8
const (
	CmdTypeStartTunn CmdType = iota
	CmdTypeStopTunn
	CmdTypeEnableLocalProxy
	CmdTypeDisableLocalProxy
	CmdTypeEnableTunnelProxy
	CmdTypeDisableTunnelProxy
)

type CheckCmd struct {
	CheckString		string 	`json:"check_string"`
	UTCTimeNow		string 	`json:"utc_time_now"`
}

type TunnelToggle struct {
	ServerName 	string	`json:"server_name"`
	ServerPort 	int		`json:"server_port"`
	Path 		string	`json:"path"`
}

type Config struct {
	CheckString       		string `json:"check_string"`
	PublicKeyPath     		string `json:"public_key_path"`
	H2TunnelClientIP  		string `json:"h2_tunnel_client_ip"`
	H2TunnelClientCmdPort 	int    `json:"h2_tunnel_client_cmd_port"`
}

// 允许的命令
var validCmds = map[string]string{
	"StartTunn":        "Start up the tunnel",
	"StopTunn":         "Stop the tunnel",
	"EnableLocalProxy": "Enable the use of local proxy for output byte streams",
	"DisableLocalProxy": "Disable the use of local proxy for output byte streams",
	"EnableTunnelProxy": "Enable the use of local proxy for tunnel",
	"DisableTunnelProxy": "Disable the use of local proxy for tunnel",
}

const maxUDPPayload = 1400 // 限制为单个IP包大小以内，避免分片

var gRSAEncryptor *rsa_demo.RSAEncryptor
var gConn *net.UDPConn
var gConfig *Config


func main() {
	// 定义命令行参数
	configPath := flag.String("config", "", "Path to configuration file (JSON)")
	cmd := flag.String("cmd", "", "Command to execute")

	serverName := flag.String("server-name", "", "Server name (required for StartTunn/StopTunn)")
	serverPort := flag.Int("server-port", 0, "Server port (required for StartTunn/StopTunn)")
	path := flag.String("path", "", "Path (required for StartTunn/StopTunn)")

	help := flag.Bool("help", false, "Show help")

	flag.Parse()

	// 如果带了 --help
	if *help {
		printHelp()
		return
	}

	// 检查 --config
	if *configPath == "" {
		log.Println("Error: --config is required")
		printHelp()
		os.Exit(1)
	}

	// 读取配置
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}
	gConfig = cfg

	// 检查 --cmd
	if *cmd == "" {
		log.Println("Error: --cmd is required")
		printHelp()
		os.Exit(1)
	}

	// 判断是否在有效命令范围
	desc, ok := validCmds[*cmd]
	if !ok {
		log.Printf("Error: invalid --cmd value '%s'\n", *cmd)
		printHelp()
		os.Exit(1)
	}
	log.Printf("Executing command: %s (%s)\n", *cmd, desc)

	gRSAEncryptor = &rsa_demo.RSAEncryptor{}
	if err := gRSAEncryptor.LoadPublicKey(gConfig.PublicKeyPath); err != nil {
		log.Printf("load pub:", err)
		os.Exit(1)
	}

	addrStr := gConfig.H2TunnelClientIP + ":" + strconv.Itoa(gConfig.H2TunnelClientCmdPort)
	addr, _ := net.ResolveUDPAddr("udp", addrStr)
	gConn, _ = net.DialUDP("udp", nil, addr)
	defer gConn.Close()

	// 如果是 StartTunn 或 StopTunn，检查额外参数
	if *cmd == "StartTunn" || *cmd == "StopTunn" {
		if *serverName == "" || *serverPort == 0 || *path == "" {
			log.Println("Error: StartTunn/StopTunn requires --server-name, --server-port, and --path")
			printHelp()
			os.Exit(1)
		}
		log.Printf("Server Name: %s, Server Port: %d, Path: %s\n", *serverName, *serverPort, *path)

		// exec StartTunn / StopTunn
		check, err := checkCmd()
		if err != nil {
			log.Printf("checkCmd. err: %v", err)
			os.Exit(1)
		}
		var cmdType CmdType
		if *cmd == "StopTunn" {
			cmdType = CmdTypeStopTunn
		} else if *cmd == "StartTunn" {
			cmdType = CmdTypeStartTunn
		}
		toggleTunn, err := toggleTunnel(cmdType, *serverName, *serverPort, *path)
		if err != nil {
			log.Printf("toggleTunnel. err: %v", err)
			os.Exit(1)
		}
		payload := append(check , toggleTunn...)
		gConn.Write(payload)
	} else  {
		check, err := checkCmd()
		if err != nil {
			log.Printf("checkCmd. err: %v", err)
			os.Exit(1)
		}
		var cmdType CmdType
		if *cmd == "EnableLocalProxy" {
			cmdType = CmdTypeEnableLocalProxy
		} else if *cmd == "DisableLocalProxy" {
			cmdType = CmdTypeDisableLocalProxy
		} else if *cmd == "EnableTunnelProxy" {
			cmdType = CmdTypeEnableTunnelProxy
		} else if *cmd == "DisableTunnelProxy" {
			cmdType = CmdTypeDisableTunnelProxy
		}
		cmdBody, err := otherCmd(cmdType)
		if err != nil {
			fmt.Printf("otherCmd err: %v", err)
			os.Exit(1)
		}
		payload := append(check, cmdBody...)
		gConn.Write(payload)
	}
	// log.Println("Config and command validated successfully ✅")
	return
}


func toggleTunnel(cmdType CmdType, servName string, servPort int, tunnPath string) ([]byte, error){
	tunnToggle := TunnelToggle {
		ServerName: servName, 
		ServerPort: servPort,
		Path: tunnPath,
	}
	body, err := json.Marshal(tunnToggle)
	if err != nil {
		fmt.Printf("Marshal err: %v\n", err)
		return []byte{}, err
	}

	cmdBuf := new(bytes.Buffer)
	if err := binary.Write(cmdBuf, binary.BigEndian, byte(cmdType)); err != nil {
		fmt.Printf("binary.Write err: ", err)
		return []byte{}, err
	}
	if err := binary.Write(cmdBuf, binary.BigEndian, uint32(len(body))); err != nil {
		fmt.Printf("binary.Write err: ", err)
		return []byte{}, err
	}
	if _, err := cmdBuf.Write(body); err != nil {
		fmt.Printf("cmdBuf.Write err: ", err)
		return []byte{}, err
	}
	if cmdBufCipher, err := gRSAEncryptor.Encrypt(cmdBuf.Bytes()); err != nil {
		fmt.Printf("Encrypt err: %v", err)
		return []byte{}, err
	} else {
		return cmdBufCipher, nil
	}
}

func otherCmd(cmd CmdType) ([]byte, error) {
	cmdBuf := new(bytes.Buffer)
	if err := binary.Write(cmdBuf, binary.BigEndian, byte(cmd)); err != nil {
		fmt.Printf("binary.Write err: ", err)
		return []byte{}, err
	}
	if err := binary.Write(cmdBuf, binary.BigEndian, uint32(0)); err != nil {
		fmt.Printf("binary.Write err: ", err)
		return []byte{}, err
	}
	if cmdBufCipher, err := gRSAEncryptor.Encrypt(cmdBuf.Bytes()); err != nil {
		fmt.Printf("Encrypt err: %v", err)
		return []byte{}, err
	} else {
		return cmdBufCipher, nil
	}

}

func checkCmd() ([]byte, error) {
	var ret []byte
	checkCmd := CheckCmd {
		CheckString: gConfig.CheckString,
		UTCTimeNow: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(checkCmd)
	if err != nil {
		fmt.Printf("Marshal err: %v\n", err)
		return ret, err
	}
	if bodyCipher, err := gRSAEncryptor.Encrypt(body); err != nil {
		fmt.Printf("Encrypt err: %v", err)
		return ret, err
	} else {
		// fmt.Printf("conn write cipher, len: %d\n", len(cmdBufCipher))
		// gConn.Write(cmdBufCipher)
		ret = bodyCipher
		return ret, nil
	}
}


// 读取配置文件
func loadConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("open config file error: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config error: %w", err)
	}

	return &cfg, nil
}

// 校验配置
func validateConfig(cfg *Config) error {
	if _, err := os.Stat(cfg.PublicKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("public key file does not exist: %s", cfg.PublicKeyPath)
	}
	if ip := net.ParseIP(cfg.H2TunnelClientIP); ip == nil {
		return fmt.Errorf("invalid h2_tunnel_client_ip: %s", cfg.H2TunnelClientIP)
	}
	if cfg.H2TunnelClientCmdPort <= 0 || cfg.H2TunnelClientCmdPort > 65535 {
		return fmt.Errorf("invalid h2_tunnel_client_cmd_port: %d", cfg.H2TunnelClientCmdPort)
	}
	return nil
}

// 打印帮助
func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  --config ./h2_tunnel_cmd_config.json   (required)")
	fmt.Println("  --cmd CMD                              (required)")
	fmt.Println("    CMD options:")
	for k, v := range validCmds {
		fmt.Printf("      %-20s  %s\n", k, v)
	}
	fmt.Println("\n  For StartTunn/StopTunn, also required:")
	fmt.Println("    --server-name $SERVER-NAME --server-port $SERVER-PORT --path $PATH")
}