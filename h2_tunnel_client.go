package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"encoding/binary"
	"errors"
	"time"
	"os"
	"strconv"
	"net/url"
	"encoding/json"
	"bytes"
	"flag"
	
	"golang.org/x/net/http2"

	"H2Tunnel/rsa_demo"
)

// 定义类型枚举
type TunnState uint8
const (
	TunnStateStopped TunnState = iota
	TunnStateStarting
	TunnStateRunning
	TunnStateStopping
)

// TunnelServerConfig 表示单个隧道服务器配置
type TunnelServerConfig struct {
	Name 		string 	`json:"name"`
	Port 		int    	`json:"port"`
	Path 		string 	`json:"path"`
	Status 		int		`json:"status"`
	wg 			sync.WaitGroup
	ToQuit		bool
	tunnState 	TunnState
}

// Config 表示整个配置文件
type Config struct {
	TunnelProxyEndPoint 		string					`json:"tunnel_proxy_end_point"`
	LocalProxyEndPoint  		string					`json:"local_proxy_end_point"`
	CheckString					string					`json:"check_string"`
	H2TunnelClientCmdPort 		int						`json:"h2_tunnel_client_cmd_port"`
	PrivateKeyPath 				string					`json:"private_key_path"`
	PublicKeyPath 				string 					`json:"public_key_path"`
	Debug               		bool					`json:"debug"`
	TunnelServers       		[]TunnelServerConfig	`json:"tunnel_server"`
}

type CmdType uint8
const (
	CmdTypeStartTunn CmdType = iota
	CmdTypeStopTunn
	CmdTypeEnableLocalProxy
	CmdTypeDisableLocalProxy
	CmdTypeEnableTunnelProxy
	CmdTypeDisableTunnelProxy
)
func (c CmdType) String() string {
	switch c {
	case CmdTypeStartTunn:
		return "StartTunn"
	case CmdTypeStopTunn:
		return "StopTunn"
	case CmdTypeEnableLocalProxy:
		return "EnableLocalProxy"
	case CmdTypeDisableLocalProxy:
		return "DisableLocalProxy"
	case CmdTypeEnableTunnelProxy:
		return "EnableTunnelProxy"
	case CmdTypeDisableTunnelProxy:
		return "DisableTunnelProxy"
	default:
		return fmt.Sprintf("UnknownCmd(%d)", c)
	}
}

type CheckCmd struct {
	CheckString		string 	`json:"check_string"`
	UTCTimeNow		string 	`json:"utc_time_now"`
}

type TunnelToggle struct {
	ServerName 	string	`json:"server_name"`
	ServerPort 	int		`json:"server_port"`
	Path 		string	`json:"path"`
}

type ConnMap struct {
    mu   sync.Mutex
    conns map[uint32]net.Conn
	next_id	uint32
}

const maxUDPPayload = 1400 // 限制为单个IP包大小以内，避免分片

var gConfig *Config
var gConnMap *ConnMap
var muConnMap  sync.Mutex
var gPipeReader *io.PipeReader
var gPipeWriter *io.PipeWriter
var gRSAHandler *rsa_demo.RSAHandler
var gLocalProxy bool = true
var gTunnelProxy bool = true


func main() {
	var err error

	configPath := flag.String("config", "", "Path to configuration file (JSON)")
	flag.Parse()
	// 检查 --config
	if *configPath == "" {
		log.Println("Error: --config is required")
		// printHelp()
		os.Exit(1)
	}

/*     // 生成带时间戳的日志文件名
    timestamp := time.Now().Format("20060102_150405.000") // 年月日_时分秒毫秒
    fileName := fmt.Sprintf("H2Tunnel_%s.log", timestamp)

    // 打开或创建日志文件
	var logFile *os.File
    logFile, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Open log file failed: %v", err)
    }
    defer logFile.Close()

    // 设置日志输出到文件
    log.SetOutput(logFile) */
    // 设置日志前缀和时间格式
    // log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.SetFlags(log.Lshortfile)
    log.Printf("pid: %d", os.Getpid())

	gConfig, err = LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}

	log.Printf("Config: %#v\n", gConfig)
	bs, _ := json.Marshal(gConfig)
	var out bytes.Buffer
	json.Indent(&out, bs, "", "\t")
	log.Printf("Config: \n%v\n", out.String())

	if false == IsValidIPOrDomain(gConfig.LocalProxyEndPoint) {
		log.Printf("Local proxy endpoint [%s] is illegal", gConfig.LocalProxyEndPoint)
	}

	// 打印每个 tunnel_server 的 name 是否为合法 IP/域名
	for _, server := range gConfig.TunnelServers {
		if IsValidIPOrDomain(server.Name) {
			log.Printf("Server [%s] is legal ip or domain", server.Name)
		} else {
			log.Printf("Server [%s] is illegal", server.Name)
		}
	}
	if len(gConfig.TunnelServers) == 0 {
		log.Printf("Length of Config TunnelServers option shouldn't be zero")
		// return
	}

	// 加密+解密示例
	gRSAHandler = &rsa_demo.RSAHandler{}
	if err := gRSAHandler.LoadPublicKey(gConfig.PublicKeyPath); err != nil {
		log.Fatal("LoadPublicKey:", err)
	}
	if err := gRSAHandler.LoadPrivateKey(gConfig.PrivateKeyPath); err != nil {
		log.Fatal("LoadPrivateKey:", err)
	}

	gConnMap = NewConnMap()
	for i := 0; i < len(gConfig.TunnelServers); i++ {
		gConfig.TunnelServers[i].ToQuit = false
		gConfig.TunnelServers[i].tunnState = TunnStateStarting
		go h2TunnelClient(i)
	}

	udpServer()
}


func udpServer() {
	log.Printf("[UdpCmdServer] UDP Listener start on: %d\n", gConfig.H2TunnelClientCmdPort)
	addr, err := net.ResolveUDPAddr("udp", ":" + strconv.Itoa(gConfig.H2TunnelClientCmdPort))
	if err != nil {
		log.Printf("ResolveUDPAddr err: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("ListenUDP err: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, maxUDPPayload)

	for {
		// ReadFromUDP 一次只会读一个包，buf不够就会丢弃数据
		n, _, _ := conn.ReadFromUDP(buf)
		// log.Printf("[UdpCmdServer] 收到 %d 字节 来自 %s\n", n, remote)

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// 每 256 字节作为一段密文
		for i := 0; i + 256 <= len(packet); i += 256 {
			order := i / 256
			cipher := packet[i : i + 256]
			// plain, err := decrypt(priv, cipher)
			plainText, err := gRSAHandler.Decrypt(cipher)
			if err != nil {
				log.Printf("[UdpCmdServer] The %dth data decrypt failed: %v\n", i / 256 + 1, err)
				break
			}
			log.Printf("[UdpCmdServer] The %dth plain text: %s\n", i / 256 + 1, string(plainText))

			if 0 == order {
				var checkCmd CheckCmd
				err := json.Unmarshal(plainText, &checkCmd)
				if err != nil {
					log.Printf("[UdpCmdServer] Unmarshal check cmd failed: %v", err)
					break
				} else {
					ok, err := CompareUTCTime(checkCmd.UTCTimeNow, time.RFC3339, 10 * time.Second)
					if err != nil {
						log.Println("[UdpCmdServer] CompareUTCTime Error:", err)
						break
					}
					if !ok {
						log.Printf("[UdpCmdServer] CompareUTCTime Check time diffrence is to large.\n")
						break
					}
					if gConfig.CheckString != checkCmd.CheckString {
						log.Printf("[UdpCmdServer] Check string:\"%s\" not match.\n", checkCmd.CheckString)
						break
					}
					// log.Printf("Check cmd PASSED: %v.\n", checkCmd)
				}

			} else if 1 == order {
				var cmdType CmdType
				plainBuf := bytes.NewReader(plainText)

				if err := binary.Read(plainBuf, binary.BigEndian, &cmdType); err != nil {
					log.Printf("[UdpCmdServer] Read plain buf: %+v\n", err)
					break
				}	
				log.Printf("[UdpCmdServer] CmdType: %s\n", cmdType)
				var cmdLength uint32 = 0
				if err := binary.Read(plainBuf, binary.BigEndian, &cmdLength); err != nil {
					log.Printf("[UdpCmdServer] Read plain buf: %+v\n", err)
					break
				}	
				// log.Printf("[UdpCmdServer] cmdLength: %d\n", cmdLength)
				if cmdType == CmdTypeStartTunn || cmdType == CmdTypeStopTunn {
					body := make([]byte, cmdLength)
					if err := binary.Read(plainBuf, binary.BigEndian, &body); err != nil {
						log.Printf("[UdpCmdServer] Read plain buf: %+v\n", err)
						break
					}
					//var startTunn interface{}
					var toggle TunnelToggle
					err := json.Unmarshal(body, &toggle)
					if err != nil {
						log.Printf("[UdpCmdServer] Unmarshal failed: %v\n", err)
						break
					}
					log.Printf("[UdpCmdServer] %v\n", toggle)
					for i := 0; i < len(gConfig.TunnelServers); i++ {
						if gConfig.TunnelServers[i].Name == toggle.ServerName && gConfig.TunnelServers[i].Port == toggle.ServerPort {
							// 打开或关闭
							if cmdType == CmdTypeStartTunn && gConfig.TunnelServers[i].tunnState == TunnStateStopped {
								gConfig.TunnelServers[i].ToQuit = false
								gConfig.TunnelServers[i].tunnState = TunnStateStarting
								go h2TunnelClient(i)
								log.Printf("[UdpCmdServer] StartTunn. Started H2TunnelClient goroutine.\n")
							} else if cmdType == CmdTypeStopTunn && gConfig.TunnelServers[i].tunnState == TunnStateRunning {
								gConfig.TunnelServers[i].ToQuit = true
								gConfig.TunnelServers[i].wg.Wait()
								gConfig.TunnelServers[i].ToQuit = false
								gConfig.TunnelServers[i].tunnState = TunnStateStopped
								log.Printf("[UdpCmdServer] StopTunn. All goroutine quited.\n")
							}
							break
						}
					}
				} else if cmdType == CmdTypeEnableLocalProxy {
					gLocalProxy = true
					log.Printf("[UdpCmdServer] Enabled local proxy.\n")
				} else if cmdType == CmdTypeDisableLocalProxy {
					gLocalProxy = false
					log.Printf("[UdpCmdServer] Disabled local proxy.\n")
				} else if cmdType == CmdTypeEnableTunnelProxy {
					gTunnelProxy = true
					log.Printf("[UdpCmdServer] Enabled tunnel proxy.\n")
				} else if cmdType == CmdTypeDisableTunnelProxy {
					gTunnelProxy = false
					log.Printf("[UdpCmdServer] Disable tunnel proxy.\n")
				}
			}

		}
	}
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("LoadConfig failed: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("LoadConfig. Unmarshal failed: %w", err)
	}

	return &cfg, nil
}

func IsValidIPOrDomain(s string) bool {
	// 先判断是否是合法 IP
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	// 如果不是 IP，就简单判断是否是合法域名
	// net.LookupHost 能区分合法域名，但会触发 DNS 查询
	// 这里用简单的规则：长度合法 + 不能包含空格
	if len(s) > 0 && len(s) <= 253 {
		return true
	}
	return false
}

func h2TunnelClient(serverIndex int) {
	gConfig.TunnelServers[serverIndex].wg.Add(1)
	defer gConfig.TunnelServers[serverIndex].wg.Done()
	// 自带锁，不需要加锁
	pr, pw := io.Pipe()
	gPipeReader = pr
	gPipeWriter = pw

	var tunnelClient http.Client 
	var proxyUrl *url.URL
	proxyAvailable := true
	if len(gConfig.TunnelProxyEndPoint) == 0 {
		proxyAvailable = false
	} else { 
		if u, err := url.Parse(gConfig.TunnelProxyEndPoint); err != nil {
			proxyAvailable = false
		} else {
			proxyAvailable = true
			proxyUrl = u
		}
	}
	if gTunnelProxy && proxyAvailable {
		httpTransport := &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		if err := http2.ConfigureTransport(httpTransport); err != nil {
			log.Fatal(err)
		}
		tunnelClient = http.Client{
			Transport: httpTransport,
		}
	} else {
		tunnelClient = http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	reqUrl := "https://" + gConfig.TunnelServers[serverIndex].Name + ":" + strconv.Itoa(gConfig.TunnelServers[serverIndex].Port) + gConfig.TunnelServers[serverIndex].Path
	req, err := http.NewRequest("POST", reqUrl, pr)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "keep-alive")

	resp, err := tunnelClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := resp.Body.Close()
		log.Printf("[H2TunnelClient] Close resp.Body: %v\n", err)
	}()
	log.Println("[H2TunnelClient] H2Tunnel Response Status: ", resp.Status, resp.Proto)
	gConfig.TunnelServers[serverIndex].tunnState = TunnStateRunning

	go func() {
		gConfig.TunnelServers[serverIndex].wg.Add(1)
		defer gConfig.TunnelServers[serverIndex].wg.Done()
		for {
			// warp 10s 就断开连接了，Read(resp.Body) 会返回 unexpected EOF
			// 这里每 5s 发一个包当作保活
			msg_keepalive_byte, _ := NewKeepAlive().ToBytes()
			gPipeWriter.Write(msg_keepalive_byte)
			for i := 50; i > 0; i-- {
				time.Sleep(100 * time.Millisecond)
				if gConfig.TunnelServers[serverIndex].ToQuit {
					return
				}
			}
		}
	}()

	var header [9]byte
	for {
		if gConfig.TunnelServers[serverIndex].ToQuit {
			break
		}
		// 读取头部（阻塞直到有9字节）
		if _, err := io.ReadFull(resp.Body, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("[H2TunnelClient] Server stream ended")
				break
			}
			log.Println("[H2TunnelClient] Read header error:", err)
			break
		}
		msg_type := MessageType(header[0])
		id := binary.BigEndian.Uint32(header[1:5])
		length := binary.BigEndian.Uint32(header[5:9])
		data := make([]byte, length)
		if _, err := io.ReadFull(resp.Body, data); err != nil {
			log.Println("[H2TunnelClient] Read data error:", err)
			break
		}

		msg := Message{Type: msg_type, ID: id, Length: length, Data: data}
		if msg.Type != MsgTypeSendData {
			log.Printf("[H2TunnelClient] <%d> Type: %s, Length: %d\n", msg.ID, msg.Type, msg.Length)
		}
		if msg.Type == MsgTypeCreateDial {
			go handleHttpConnect(serverIndex, msg)
		} else if msg.Type == MsgTypeSendData && msg.ID >= 2 {
			muConnMap.Lock()
			conn, ok := gConnMap.Get(msg.ID)
			muConnMap.Unlock()
			if ok {
				n, err := conn.Write(msg.Data)
				if err != nil {
					log.Printf("[H2TunnelClient] <%d> Error writing to target connection: %v", msg.ID, err)
				}
				if n != len(msg.Data) {
					log.Printf("[H2TunnelClient]  <%d> n != len(msg.Data)", msg.ID)
				}
				// targetConn.flusher()
				// hash := md5.Sum(msg.Data)
				// log.Printf("[OUTPUT] <%d> Sent %d bytes to target connection. MD5: %s", msg.ID, n, hex.EncodeToString(hash[:]))
			}
		} else if msg.Type == MsgTypeTest {
			log.Printf("[H2TunnelClient] MsgTest: %s\n", string(msg.Data))
		} else if msg.Type == MsgTypeDestroy && msg.ID >= 2 {
			muConnMap.Lock()
			conn, ok := gConnMap.Get(msg.ID)
			muConnMap.Unlock()
			if ok {
				conn.Close()
				muConnMap.Lock()
				gConnMap.Delete(msg.ID)
				muConnMap.Unlock()
				log.Printf("[H2TunnelClient] MsgDstroy <%d> closed.\n", msg.ID)
			}
		} else if msg.Type == MsgTypeKeepAlive {
			log.Printf("[H2TunnelClient] MsgTypeKeepAlive\n")
		}

	}
}

func handleHttpConnect(serverIndex int, creaDialMess Message) {
	gConfig.TunnelServers[serverIndex].wg.Add(1)
	defer gConfig.TunnelServers[serverIndex].wg.Done()

	var cd CreateDial
	if creaDialMess.Type != MsgTypeCreateDial {
		log.Println("[HttpConnect] The first message should be CreateDial.")
		return 
	}
	_ = json.Unmarshal(creaDialMess.Data, &cd)
	log.Printf("[HttpConnect] DestHost: %s, Identification: %s\n", cd.DestHost, cd.Identification)

	var destConn net.Conn
	var dialErr error
	// 定义代理地址
	if gLocalProxy && IsValidIPOrDomain(gConfig.LocalProxyEndPoint) {
		log.Printf("[HttpConnect] Connect to proxy: %s\n", gConfig.LocalProxyEndPoint)
		destConn, dialErr = net.Dial("tcp", gConfig.LocalProxyEndPoint)
		if dialErr != nil {
			log.Printf("[HttpConnect] Dial to %s failed: %v", gConfig.LocalProxyEndPoint, dialErr)
			return 
		}
		destConn.Write([]byte("CONNECT " + cd.DestHost + " HTTP/1.1\r\n\r\n"))
		destConn.Write([]byte("Host: " + cd.DestHost + "\r\n\r\n"))
		destConn.Write([]byte("User-Agent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0\r\n\r\n"))
		destConn.Write([]byte("Proxy-Connection: Keep-Alive\r\n\r\n"))

		// buf := make([]byte, 512)
		reader := bufio.NewReader(destConn)
		line, err := reader.ReadString('\n')
		// n, err := destConn.Read(buf)
		if err != nil {
			log.Printf("[HttpConnect] Read local proxy failed: %v", err)
		} else {
			log.Printf("[HttpConnect] Read local proxy: %s", line)
		}
		line, err = reader.ReadString('\n') // HTTP Proxy数据以"\r\n\r\n"结束，这里读取第二个"\r\n"。但不读掉它也没关系
		// log.Printf("Read local proxy one more time: %s, len: %d, line[0]: %d", line, len(line), line[0])  // 打印回车键13
	} else {
		// log.Printf("Local proxy endpoint err: %v. Build Dial without proxy.", err)
		// DestHost := string(msg.Data)
		destConn, dialErr = net.Dial("tcp", cd.DestHost)
	}
	defer destConn.Close()

	if dialErr != nil {
		log.Printf("[HttpConnect] Failed to connect to %s: %v", cd.DestHost, dialErr)
		result := CreateDialResult{
			Identification: cd.Identification,
			Result: false,
			ID: 1,
			LocalAddr: "",
			RemoteAddr: "",
		}
		bin, _ := NewCreateDialResult(1, result).ToBytes()
		gPipeWriter.Write(bin)
	} else {
		muConnMap.Lock()
		id := gConnMap.Add(destConn)
		// log.Printf("Number of gConnMap.conns is %d\n", len(gConnMap.conns))
		muConnMap.Unlock()
		log.Printf("[HttpConnect] <%d> Connected to: %s, %s", id, cd.DestHost, destConn.RemoteAddr())
		result := CreateDialResult{
			Identification: cd.Identification,
			Result: true,
			ID: id,
			LocalAddr: destConn.LocalAddr().String(),
			RemoteAddr: destConn.RemoteAddr().String(),
		}
		bin, _ := NewCreateDialResult(1, result).ToBytes()
		gPipeWriter.Write(bin)

		// 生成MsgID，构造map[ID] Conn，后续的包根据ID查找Conn收发。
		// 新建线程专门收每个请求的包，当收到EOF时，需要新定义的一个MsgTypeEOF来关闭这个MsgID，MsgTypeEOF可以是服务端发，也可以是客户端发。
		buf_in := make([]byte, 512 * 1024)
		reader := bufio.NewReader(destConn)
		for {
			if gConfig.TunnelServers[serverIndex].ToQuit {
				break
			}
			n, err := reader.Read(buf_in)
			if err != nil {
				log.Printf("[HttpConnect] <%d> Error reading from target connection: %v", id, err)
				// destConn.Close()
				destory := NewDestroy(id)
				destory_byte, _ := destory.ToBytes()
				gPipeWriter.Write(destory_byte)
				muConnMap.Lock()
				gConnMap.Delete(id)
				muConnMap.Unlock()
				return
			}
			// log.Printf("[HttpConnect] <%d> Received %d bytes from target connection", id, n)
			if n > 0 {
				//msg_recv := Message{Type: ReceiveData, Length: uint32(n), Data: buf_in[:n]}
				msg_recv := NewReceiveData(id, buf_in[:n])
				msg_recv_byte, _ := msg_recv.ToBytes()
				gPipeWriter.Write(msg_recv_byte)
			} else {
				log.Printf("[HttpConnect] <%d> No data received from target connection", id)
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

// CompareUTCTime checks whether a UTC time string is within maxDiff of current UTC now.
func CompareUTCTime(timeStr string, layout string, maxDiff time.Duration) (bool, error) {
	// 解析输入时间字符串
	parsedTime, err := time.Parse(layout, timeStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse time: %v", err)
	}

	// 获取当前 UTC 时间
	now := time.Now().UTC()

	// 计算时间差的绝对值
	diff := now.Sub(parsedTime)
	if diff < 0 {
		diff = -diff
	}

	// 判断是否在允许的误差范围内
	return diff <= maxDiff, nil
}

