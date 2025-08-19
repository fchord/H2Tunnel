

package main

import (
	"fmt"
	// "crypto/tls"
	// "io"
	// "log"
	// "net/http"
	// "net"
	// "time"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	// "strings"

	// "golang.org/x/net/http2"
)

// 定义类型枚举
type MessageType uint8

const (
	MsgTypeCreateDial MessageType = iota
	MsgTypeCreateDialResult
	MsgTypeSendData
	MsgTypeReceiveData
	MsgTypeDestroy			/* 结束一次连接并释放ID。可能的原因有：目标服务器关闭连接；发起端关闭连接。 */
	MsgTypeKeepAlive		/* 维护隧道连通。ID=0. */
	MsgTypeTest
)

// 为枚举类型实现 String() 方法
func (m MessageType) String() string {
    switch m {
    case MsgTypeCreateDial:
        return "MsgTypeCreateDial"
    case MsgTypeCreateDialResult:
        return "MsgTypeCreateDialResult"
    case MsgTypeSendData:
        return "MsgTypeSendData"
    case MsgTypeReceiveData:
        return "MsgTypeReceiveData"
    case MsgTypeDestroy:
        return "MsgTypeDestroy"
    case MsgTypeKeepAlive:
        return "MsgTypeKeepAlive"
    case MsgTypeTest:
        return "MsgTypeTest"
    default:
        return fmt.Sprintf("MessageType(%d)", int(m))
    }
}

type Message struct {
	Type   MessageType
	ID 	   uint32 /* 0: 专用于H2隧道自身维护。 1: 专用于发起 MsgTypeCreateDial 消息。 >1: 用于标识已建立的tcp连接。 */ 
	Length uint32
	Data   []byte
}

/* 请求创建一个 tcp连接 */
type CreateDial struct {
	Identification string 	`json: "identification"`   /* 用于标识一次连接请求，由发起方生成 */
	DestHost string			`json: "dest_host"`
}

/* tcp连接创建结果 */
type CreateDialResult struct {
	Identification string 	`json: "identification"`   /* 用于标识一次连接请求 */
	Result bool 			`json: "result"`		   /* 创建net.Dial是否成功 */
	ID uint32				`json: "id"`			   /* H2TunnelClient生成的tcp连接的唯一标识，后续需要写入Message.ID */
	LocalAddr  string 		`json: "local_addr"`	   /* tcp连接的本地地址 */
	RemoteAddr string 		`json: "remote_addr"`	   /* tcp连接的远程地址 */
}

// 序列化
func (m *Message) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, m.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, m.ID); err != nil {
		return nil, err
	}
	m.Length = uint32(len(m.Data))
	if err := binary.Write(buf, binary.BigEndian, m.Length); err != nil {
		return nil, err
	}
	if _, err := buf.Write(m.Data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// 反序列化
func FromBytes(b []byte) (*Message, error) {
	buf := bytes.NewReader(b)
	var msg Message
	if err := binary.Read(buf, binary.BigEndian, &msg.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &msg.ID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &msg.Length); err != nil {
		return nil, err
	}
	if msg.Length > uint32(len(b)) - 9 /* len(msg.Type) - len(msg.ID) - len(msg.Length) */ {
		return nil, errors.New("invalid length")
	}
	msg.Data = make([]byte, msg.Length)
	if _, err := buf.Read(msg.Data); err != nil {
		return nil, err
	}
	return &msg, nil
}

// 构造四种消息
func NewCreateDial(host string, iden string) *Message {
	cd := CreateDial{
		Identification: iden,
		DestHost: host,
	}
	jcd, _ := json.Marshal(cd)
	return &Message{Type: MsgTypeCreateDial, ID: 1, Data: []byte(jcd)}
}

func NewCreateDialResult(id uint32, result CreateDialResult) *Message {
	jResult, _ := json.Marshal(result)
	return &Message{Type: MsgTypeCreateDialResult, ID: id, Data: jResult}
}

func NewSendData(id uint32, data []byte) *Message {
	return &Message{Type: MsgTypeSendData, ID: id, Data: data}
}

func NewReceiveData(id uint32, data []byte) *Message {
	return &Message{Type: MsgTypeReceiveData, ID: id, Data: data}
}

func NewTest(id uint32, data []byte) *Message {
	return &Message{Type: MsgTypeTest, ID: id, Data: data}
}

func NewKeepAlive() *Message {
	return &Message{Type: MsgTypeKeepAlive, ID: 0, Data: []byte("KEEPALIVE")}
}

func NewDestroy(id uint32) *Message {
	return &Message{Type: MsgTypeDestroy, ID: id, Data: []byte("")}
}

/* 
func ParseStream(r io.Reader) error {
	var header [5]byte
	for {
		// 读取头部（阻塞直到有5字节）
		if _, err := io.ReadFull(r, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		msgType := MessageType(header[0])
		length := binary.BigEndian.Uint32(header[1:5])

		data := make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}

		msg := Message{Type: msgType, Length: length, Data: data}
		fmt.Printf("[Parsed] Type=%v, Length=%d, Data=%q\n", msg.Type, msg.Length, string(msg.Data))
	}
}
 */