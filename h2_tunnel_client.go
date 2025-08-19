package main

import (
	"bufio"
	"crypto/tls"
	// "encoding/gob"
	// "flag"
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
	// "crypto/md5"
	// "encoding/hex"	
	"golang.org/x/net/http2"
)

type Config struct {
	TunnelServerIP    string    			`json:"tunnel_server_ip"`
	TunnelServerPort  int	    			`json:"tunnel_server_port"`
	TunnelServerPath  string    			`json:"tunnel_server_path"`
	TunnelProxyEndPoint	  string 			`json:"tunnel_proxy_end_point"`
	Debug 			  bool					`json:"debug"`
}


// 建立 CONNECT 隧道请求结构
type ConnectTunnelRequest struct {
	TargetAddr string
}

var tunnelWriter io.Writer
var tunnelReader io.Reader
var tunnelFlusher http.Flusher
var tunnelLock sync.Mutex
var tunnelUpChan chan byte
var tunnelDownChan chan byte

// 使用 sync.Mutex 保护 map 的并发访问
type ConnMap struct {
    mu   sync.Mutex
    conns map[uint32]net.Conn
	next_id	uint32
}

var gConfig *Config

var gConnMap *ConnMap
var muConnMap  sync.Mutex


var gPipeReader *io.PipeReader
var gPipeWriter *io.PipeWriter


func main() {

    // 生成带时间戳的日志文件名
    timestamp := time.Now().Format("20060102_150405.000") // 年月日_时分秒毫秒
    fileName := fmt.Sprintf("H2Tunnel_%s.log", timestamp)

    // 打开或创建日志文件
    logFile, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Open log file failed: %v", err)
    }
    defer logFile.Close()

    // 设置日志输出到文件
    log.SetOutput(logFile)
    // 设置日志前缀和时间格式
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
    log.Printf("pid: %d", os.Getpid())


	// var err error
	gConfig, err = LoadConfig("h2_tunnel_client_config.json")
	if err != nil {
		panic(err)
	}

	log.Println("Config loaded:")
	log.Printf("	TunnelServerIP: %s\n", gConfig.TunnelServerIP)
	log.Printf("	TunnelServerPort: %d\n", gConfig.TunnelServerPort)
	log.Printf("	TunnelServerPath: %s\n", gConfig.TunnelServerPath)
	log.Printf("	TunnelProxyEndPoint: %s\n", gConfig.TunnelProxyEndPoint)
	log.Printf("	Debug: %v\n", gConfig.Debug)

	gConnMap = NewConnMap()
	h2TunnelClient()
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func h2TunnelClient() {
	// 自带锁，不需要加锁
	pr, pw := io.Pipe()
	gPipeReader = pr
	gPipeWriter = pw

	proxy_url, _ := url.Parse(gConfig.TunnelProxyEndPoint)
	var client http.Client 
	use_proxy := true
	if use_proxy == true {
		httpTransport := &http.Transport{
			Proxy: http.ProxyURL(proxy_url),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		if err := http2.ConfigureTransport(httpTransport); err != nil {
			log.Fatal(err)
		}
		client = http.Client{
			Transport: httpTransport,
		}
	} else {
		client = http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	req, err := http.NewRequest("POST", "https://" + gConfig.TunnelServerIP + ":" + strconv.Itoa(gConfig.TunnelServerPort) + gConfig.TunnelServerPath, pr)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	log.Println("Response Status: ", resp.Status, resp.Proto)

	go func() {
		for {
			// warp 10s 就断开连接了，Read(resp.Body) 会返回 unexpected EOF
			// 这里每 5s 发一个包当作保活
			msg_keepalive_byte, _ := NewKeepAlive().ToBytes()
			gPipeWriter.Write(msg_keepalive_byte)
			time.Sleep(5 * time.Second)
		}
	}()

	var header [9]byte
	for {
		// 读取头部（阻塞直到有9字节）
		// log.Println("[0] Read header from tunnel")
		if _, err := io.ReadFull(resp.Body, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("Server stream ended")
				break
			}
			log.Println("Read header error:", err)
			break
		}
		msg_type := MessageType(header[0])
		id := binary.BigEndian.Uint32(header[1:5])
		length := binary.BigEndian.Uint32(header[5:9])
		data := make([]byte, length)
		if _, err := io.ReadFull(resp.Body, data); err != nil {
			log.Println("Read data error:", err)
			break
		}

		msg := Message{Type: msg_type, ID: id, Length: length, Data: data}
		if msg.Type != MsgTypeSendData {
			fmt.Printf("[Parsed] <%d> Type: %s, Length: %d\n", msg.ID, msg.Type, msg.Length)
		}
		if msg.Type == MsgTypeCreateDial {
			go handleHttpConnect(msg)
		} else if msg.Type == MsgTypeSendData && msg.ID >= 2 {
			muConnMap.Lock()
			conn, ok := gConnMap.Get(msg.ID)
			muConnMap.Unlock()
			if ok {
				n, err := conn.Write(msg.Data)
				if err != nil {
					log.Printf("[OUTPUT] <%d> Error writing to target connection: %v", msg.ID, err)
				}
				if n != len(msg.Data) {
					log.Printf("[OUTPUT] <%d> n != len(msg.Data)", msg.ID)
				}
				// targetConn.flusher()
				// hash := md5.Sum(msg.Data)
				// log.Printf("[OUTPUT] <%d> Sent %d bytes to target connection. MD5: %s", msg.ID, n, hex.EncodeToString(hash[:]))
			}
		} else if msg.Type == MsgTypeTest {
			log.Printf("Data=%s\n", string(msg.Data))
		} else if msg.Type == MsgTypeDestroy && msg.ID >= 2 {
			muConnMap.Lock()
			conn, ok := gConnMap.Get(msg.ID)
			muConnMap.Unlock()
			if ok {
				conn.Close()
				muConnMap.Lock()
				gConnMap.Delete(msg.ID)
				muConnMap.Unlock()
				log.Printf("<%d> closed.\n", msg.ID)
			}
		} else if msg.Type == MsgTypeKeepAlive {
			log.Printf("MsgTypeKeepAlive\n")
		}

	}
}

func handleHttpConnect(creaDialMess Message) {
	var cd CreateDial
	if creaDialMess.Type != MsgTypeCreateDial {
		log.Println("[HttpConnect] The first message should be CreateDial.")
		return 
	}
	_ = json.Unmarshal(creaDialMess.Data, &cd)
	fmt.Printf("[HttpConnect] DestHost: %s, Identification: %s\n", cd.DestHost, cd.Identification)
	// Todo: 建立tcp连接
	// DestHost := string(msg.Data)
	destConn, err := net.Dial("tcp", cd.DestHost)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", cd.DestHost, err)
		result := CreateDialResult{
			Identification: cd.Identification,
			Result: false,
			ID: 1,
			LocalAddr: "",
			RemoteAddr: "",
		}
		// bin, _ := NewCreateDialResult(false).ToBytes()
		bin, _ := NewCreateDialResult(1, result).ToBytes()
		gPipeWriter.Write(bin)
	} else {
		muConnMap.Lock()
		id := gConnMap.Add(destConn)
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
			n, err := reader.Read(buf_in)
			if err != nil {
				log.Printf("[OUTPUT] <%d> Error reading from target connection: %v", id, err)
				destConn.Close()
				destory := NewDestroy(id)
				destory_byte, _ := destory.ToBytes()
				gPipeWriter.Write(destory_byte)
				muConnMap.Lock()
				gConnMap.Delete(id)
				muConnMap.Unlock()
				return
			}
			// log.Printf("[OUTPUT] <%d> Received %d bytes from target connection", id, n)
			if n > 0 {
				//msg_recv := Message{Type: ReceiveData, Length: uint32(n), Data: buf_in[:n]}
				msg_recv := NewReceiveData(id, buf_in[:n])
				msg_recv_byte, _ := msg_recv.ToBytes()
				gPipeWriter.Write(msg_recv_byte)
			} else {
				log.Printf("[OUTPUT] <%d> No data received from target connection", id)
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}
