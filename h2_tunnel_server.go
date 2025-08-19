package main

import (
	// "bufio"
	// "crypto/tls"
	"encoding/gob"
	// "flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	// "encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
	"os"
	"crypto/md5"
	"encoding/hex"	
	"strconv"
	// "net/url"

	// "golang.org/x/net/http2"
)

type Config struct {
	HttpProxyPort  int    		`json:"http_proxy_port"`
	HttpsProxyPort  int    		`json:"https_proxy_port"`
	TunnelServerPath  string 	`json:"tunnel_server_path"`
	Debug bool   				`json:"debug"`
}

// 请求结构
type HTTPRequestPayload struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// 建立 CONNECT 隧道请求结构
type ConnectTunnelRequest struct {
	TargetAddr string
}

var gConfig *Config

var tunnelWriter io.Writer
var tunnelReader io.Reader
var tunnelFlusher http.Flusher
var tunnelLock sync.Mutex
var tunnelUpChan chan byte
var tunnelDownChan chan byte

// var tunnMessDownChan chan Message
var tunnMessUpChan chan []byte

var mapCreaDial map[string]chan Message
var mapReceData map[uint32] *chan Message
var muReceData  sync.Mutex

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

	gConfig, err = LoadConfig("h2_tunnel_server_config.json")
	if err != nil {
		panic(err)
	}

	log.Println("Config loaded:")
	log.Printf("	HttpProxyPort: %d\n", gConfig.HttpProxyPort)
	log.Printf("	HttpsProxyPort: %d\n", gConfig.HttpsProxyPort)
	log.Printf("	TunnelServerPath: %s\n", gConfig.TunnelServerPath)
	log.Printf("	Debug: %v\n", gConfig.Debug)

	go h2TunnelTlsServer()
	h2TunnelServer()
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

func h2TunnelTlsServer() {
	tunnelUpChan = make(chan byte, 1024)
	tunnelDownChan = make(chan byte, 1024)

	mapCreaDial = make(map[string]chan Message)
	mapReceData = make(map[uint32] *chan Message)
	// tunnMessDownChan = make(chan Message, 64)
	tunnMessUpChan = make(chan []byte, 64)

	log.Println("[H2TunnServ] strconv.Itoa(gConfig.HttpsProxyPort): ", strconv.Itoa(gConfig.HttpsProxyPort))
	addr := ":" + strconv.Itoa(gConfig.HttpsProxyPort)
	log.Println("[H2TunnServ] Starting https proxy on " + addr)
	certFile := "/etc/ssl/cert.pem"
	keyFile := "/etc/ssl/key.pem"
	err := http.ListenAndServeTLS(
		addr, 
		certFile,
		keyFile,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == gConfig.TunnelServerPath && r.Method != http.MethodConnect {
			handleOverseasV1(w, r)
		} else {
			handleRequest(w, r)
		}
	}))
	if err != nil {
		log.Fatal("[H2TunnServ] ListenAndServeTLS: ", err)
	}
}

func h2TunnelServer() {
	addr := ":" + strconv.Itoa(gConfig.HttpProxyPort)
	log.Println("[H2TunnServ] Starting http proxy on " + addr)
	err := http.ListenAndServe(
		addr, 
		http.HandlerFunc(handleRequest))
	if err != nil {
		log.Fatal("[H2TunnServ] ListenAndServe: ", err)
	}
}

func handleOverseasV1(w http.ResponseWriter, r *http.Request) {
	log.Printf("[H2TunnServ] Proto: %s, Method: %s, Host: %s, URL: %s, RemoteAddr: %s\n", r.Proto, r.Method, r.Host, r.URL, r.RemoteAddr)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	tunnelLock.Lock()
	// tunnelWriter = w
	// tunnelReader = r.Body
	// tunnelFlusher = w.(http.Flusher)
	tunnelLock.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

    go func() {
		// chunk := make([]byte, 4096)
        for {		
			var header [9]byte
			// 读取头部（阻塞直到有9字节）
			if _, err := io.ReadFull(r.Body, header[:]); err != nil {
				if errors.Is(err, io.EOF) {
					log.Println("[H2TunnServ] Tunnel EOF")
					break
				}
				log.Println("[H2TunnServ] Tunnel Read error:", err)
				break
			}
			msg_type := MessageType(header[0])
			id := binary.BigEndian.Uint32(header[1:5])
			length := binary.BigEndian.Uint32(header[5:9])
			// log.Printf("[H2TunnServ] Received msg_type: %s, id: %d, length: %d\n", msg_type, id, length)
			data := make([]byte, length)
			if _, err := io.ReadFull(r.Body, data); err != nil {
				log.Println("[H2TunnServ] Read data error:", err)
				break
			}
			msg := Message{Type: msg_type, ID: id, Length: length, Data: data}
			if msg.Type != MsgTypeKeepAlive && false {
				log.Printf("[H2TunnServ] Received Msg: Type: %s, ID: %d, Length: %d\n", msg.Type, msg.ID, msg.Length)	
			}			
			// log.Printf("[H2TunnServ] Received Data!\n")
			if MsgTypeCreateDialResult == msg_type {
				var res CreateDialResult
				err := json.Unmarshal(msg.Data, &res)
				if err != nil {
					log.Printf("[H2TunnServ] Error unmarshalling CreateDialResult: %v", err)
				} else {
					log.Printf("[H2TunnServ] CreateDialResult: %s, Result: %t, Id: %d, LocalAddr: %s, RemoteAddr: %s", res.Identification, res.Result, res.ID, res.LocalAddr, res.RemoteAddr)
					dialChan := mapCreaDial[res.Identification]
					dialChan <- msg
				}				
			} else if MsgTypeReceiveData == msg_type || MsgTypeDestroy == msg_type {
				id := msg.ID
				muReceData.Lock()
				chanMess, ok := mapReceData[id]
				muReceData.Unlock()
				if ok {
					// log.Printf("[H2TunnServ] <%d> ReceData message insert into chanMess. Length: %d", id, len(msg.Data))
					*chanMess <- msg
				} else {
					log.Printf("[H2TunnServ] <%d> No channel found for ReceiveData with ID ", id)
				}
				
			} else if MsgTypeKeepAlive == msg_type {
				// log.Printf("[H2TunnServ] KeepAlive message received: %s", string(msg.Data))
			} else {
				log.Printf("[H2TunnServ] Received Unexpected message type: %s", msg.Type)
			}
        }
		log.Println("[H2TunnServ] Quit receive thread")
    }()

	for {
		if msg_bin, ok := <- tunnMessUpChan; !ok {
			log.Println("[H2TunnServ] Read tunnMessUpChan failed")
		} else {
			// log.Println("[H2TunnServ] Read TunnMessUpCHan, got a message")
			// bin, _ := msg.ToBytes()			
			_, err := w.Write(msg_bin)
			if err != nil {
				log.Println("[H2TunnServ] Write error: %v", err)
				return
			}			
			flusher.Flush()
		}
	}

}


func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// handleHTTPS(w, r)
		handleHTTPSRemoteV1(w, r)
	} else {
		handleHTTP(w, r)
	}
}


func handleHTTPSLocal(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "Unable to connect to destination", http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	fmt.Printf("[HTTPS] CONNECT %s\n", r.Host)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(clientConn, destConn)
	io.Copy(destConn, clientConn)

}


func handleHTTPSRemoteV1(w http.ResponseWriter, r *http.Request) {
	time_bina, _ := time.Now().MarshalBinary()
	/* if err != nil {
		log.Printf("[HTTPS] Error marshalling time: %v", err)
		time_bina = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	} */
	time_hash := md5.Sum(time_bina[:])
	// log.Printf("[HTTPS] Time hash MD5: %s\n", hex.EncodeToString(time_hash[:]) )
	/* var t time.Time
	var time_unma encoding.BinaryUnmarshaler = &t
	err = time_unma.UnmarshalBinary(time_bina)
	if err != nil {
		log.Printf("[HTTPS] Error unmarshalling time: %v", err)
	} else {
		log.Println("[HTTPS] Unmarshalled Time: ", t)
	} */

	// identification := time.Now().String()
	identification := hex.EncodeToString(time_hash[:])[:6]
	log.Printf("[HTTPS] Handling CONNECT request for %s. identification: %s", r.Host, identification)
	msg := NewCreateDial(r.Host, identification)
	mapCreaDial[identification] = make(chan Message, 1)
	// log.Printf("[HTTPS] Send CreaDial msg into tunnMessUpChan. identification: %s", identification)
	if msg_bin, err := msg.ToBytes(); err != nil {
		log.Printf("[HTTPS] Error converting CreateDial to bytes: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	} else {
		tunnMessUpChan <- msg_bin
	}
	// log.Printf("[HTTPS] Send CreaDial msg into tunnMessUpChan completed. identification: %s", identification)
	resu_mess := <- mapCreaDial[identification]
	log.Printf("[HTTPS] Got response from mapCreaDial for %s. identification: %s", r.Host, identification)
	delete(mapCreaDial, identification)
	if resu_mess.Type == MsgTypeCreateDialResult {
		var res CreateDialResult
		err := json.Unmarshal(resu_mess.Data, &res)
		if err != nil {
			log.Printf("[HTTPS] Error unmarshalling CreateDialResult: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !res.Result {
			http.Error(w, "Failed to connect to destination", http.StatusServiceUnavailable)
			return
		}
		log.Printf("[HTTPS] <%d> identification: %s, CreateDialResult: %s, Result: %t, Id: %d, LocalAddr: %s, RemoteAddr: %s", res.ID, identification, res.Identification, res.Result, res.ID, res.LocalAddr, res.RemoteAddr)
		id := res.ID
		ch := make(chan Message, 64)
		muReceData.Lock()
		mapReceData[id] = &ch
		muReceData.Unlock()

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			muReceData.Lock()
			delete(mapReceData, id)
			muReceData.Unlock()
			return
		}
		clientConn, client_rw, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			muReceData.Lock()
			delete(mapReceData, id)
			muReceData.Unlock()
			return
		}
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))	
		log.Printf("[HTTPS] <%d> Connection Established. identification: %s", id, identification)
		go func() {
			for {
				muReceData.Lock()
				ch := mapReceData[id]				
				muReceData.Unlock()
				msg_rev := <- *ch
				if msg_rev.Type == MsgTypeReceiveData { 
					// log.Printf("[HTTPS] <%d> ReceiveData message received, Data Length: %d", id, len(msg_rev.Data))
					clientConn.Write(msg_rev.Data)
				} else if msg_rev.Type == MsgTypeDestroy {
					log.Printf("[HTTPS] <%d> Destroy message received", id)
					muReceData.Lock()
					delete(mapReceData, id)
					muReceData.Unlock()
					clientConn.Close()
					return
				}
			}
		}()

		buf_out := make([]byte, 128 * 1024)
		for {
			n, err := client_rw.Read(buf_out)
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Printf("[HTTPS] <%d> Client connection closed", id)
					break
				}
				log.Printf("[HTTPS] <%d> Error reading from client: %v", id, err)
				break
			}
			if n > 0 {
				// hash := md5.Sum(buf_out[:n])
				// log.Printf("[HTTPS] <%d> Received %d bytes from client. MD5: %s\n", id, n, hex.EncodeToString(hash[:]) )
				msg_send := NewSendData(id, buf_out[:n])
				msg_bin, _ := msg_send.ToBytes()
				tunnMessUpChan <- msg_bin
			}
		}
	} else {
		log.Printf("[HTTPS] Unexpected message type: %s", resu_mess.Type)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}


func handleHTTP(w http.ResponseWriter, r *http.Request) {
	return 
	tunnelLock.Lock()
	writer := tunnelWriter
	reader := tunnelReader
	tunnelLock.Unlock()

	if writer == nil || reader == nil {
		http.Error(w, "No tunnel to output process", http.StatusBadGateway)
		return
	}
	log.Printf("[INPUT] Forwarding HTTP request to output process: %s %s\n", r.Method, r.URL.String())
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	payload := HTTPRequestPayload{
		Method: r.Method,
		URL:    r.URL.String(),
		Header: r.Header,
		Body:   bodyData,
	}
	err = gob.NewEncoder(writer).Encode(payload)
	if err != nil {
		http.Error(w, "failed to encode request", http.StatusInternalServerError)
		return
	}

	var statusCode int
	var header http.Header
	var body []byte
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&statusCode); err != nil {
		http.Error(w, "failed to decode response code", http.StatusBadGateway)
		return
	}
	if err := dec.Decode(&header); err != nil {
		http.Error(w, "failed to decode header", http.StatusBadGateway)
		return
	}
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "failed to decode body", http.StatusBadGateway)
		return
	}

	for k, v := range header {
		w.Header()[k] = v
	}
	w.WriteHeader(statusCode)
	w.Write(body)
}