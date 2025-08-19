package main

import (
	"net"
	// "sync"
    "math"
)

func NewConnMap() *ConnMap {
    return &ConnMap{
        conns: make(map[uint32]net.Conn),
        next_id: 2,
    }
}

// 添加
func (cm *ConnMap) AddWithID(id uint32, conn net.Conn) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.conns[id] = conn
}

// 添加，并自动分配一个id
func (cm *ConnMap) Add(conn net.Conn) uint32 {
    cm.mu.Lock()
    defer cm.mu.Unlock()
/* 	i := uint32(2)
	for {
		_, ok := cm.conns[i]
		if false == ok {
			break
		}
		i++
	} */
    var i uint32
    to_break := false
    for {
        _, ok := cm.conns[cm.next_id]
        if !ok {
            i = cm.next_id
            cm.conns[i] = conn
            to_break = true
        }
        cm.next_id++
        if cm.next_id == math.MaxUint32 {
            cm.next_id = 2
        }
        if to_break {
            break
        }
    }
    // cm.conns[i] = conn
	return i
}

// 查找（返回值和是否存在）
func (cm *ConnMap) Get(id uint32) (net.Conn, bool) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    conn, ok := cm.conns[id]
    return conn, ok
}

// 删除
func (cm *ConnMap) Delete(id uint32) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    delete(cm.conns, id)
}
