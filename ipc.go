package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Protocol constants are defined in protocol.go

const ipcWriteBufSize = 256 * 1024 // 256KB write buffer

type IPC struct {
	conn net.Conn

	mu       sync.Mutex
	cond     *sync.Cond
	bufs     [2][ipcWriteBufSize]byte // double buffer to avoid race
	active   int                      // which buffer is being written to (0 or 1)
	pending  int
	flushing bool
}

func NewIPC(conn net.Conn) *IPC {
	// Set socket buffer sizes for Unix socket connection
	if unixConn, ok := conn.(*net.UnixConn); ok {
		_ = unixConn.SetReadBuffer(1024 * 1024)  // 1MB
		_ = unixConn.SetWriteBuffer(1024 * 1024) // 1MB
	}

	ipc := &IPC{conn: conn}
	ipc.cond = sync.NewCond(&ipc.mu)
	return ipc
}

func (ipc *IPC) Send(cmd uint16, bufs ...[]byte) error {
	totalLen := 0
	for _, buf := range bufs {
		totalLen += len(buf)
	}
	packetSize := 2 + varintLen(uint64(totalLen)) + totalLen

	ipc.mu.Lock()

	// Wait if buffer full — if nobody is flushing, become the flusher.
	for ipc.pending+packetSize > ipcWriteBufSize {
		if !ipc.flushing {
			// Nobody is flushing; flush the current buffer to make room.
			ipc.flushing = true
			flushBuf := ipc.active
			toWrite := ipc.pending
			ipc.active = 1 - ipc.active
			ipc.pending = 0
			ipc.mu.Unlock()

			data := ipc.bufs[flushBuf][:toWrite]
			for len(data) > 0 {
				n, err := ipc.writeWithDeadline(data)
				if err != nil {
					ipc.conn.Close()
					ipc.mu.Lock()
					ipc.flushing = false
					ipc.cond.Broadcast()
					ipc.mu.Unlock()
					return err
				}
				data = data[n:]
			}

			ipc.mu.Lock()
			ipc.flushing = false
			ipc.cond.Broadcast()
			continue
		}
		ipc.cond.Wait()
	}

	// Build packet directly into active buffer (zero allocation)
	buf := &ipc.bufs[ipc.active]
	offset := ipc.pending
	binary.BigEndian.PutUint16(buf[offset:], cmd)
	offset += 2
	n := binary.PutUvarint(buf[offset:], uint64(totalLen))
	offset += n
	for _, b := range bufs {
		copy(buf[offset:], b)
		offset += len(b)
	}
	ipc.pending = offset

	if ipc.flushing {
		// Someone else is flushing, wait for completion
		for ipc.flushing {
			ipc.cond.Wait()
		}
		ipc.mu.Unlock()
		return nil
	}

	// Become the flusher
	ipc.flushing = true
	for ipc.pending > 0 {
		// Swap buffers: new writers use the other buffer while we flush this one
		flushBuf := ipc.active
		toWrite := ipc.pending
		ipc.active = 1 - ipc.active
		ipc.pending = 0
		ipc.mu.Unlock()

		// Write all pending data from the buffer we're flushing
		data := ipc.bufs[flushBuf][:toWrite]
		for len(data) > 0 {
			n, err := ipc.conn.Write(data)
			if err != nil {
				ipc.conn.Close()
				ipc.mu.Lock()
				ipc.flushing = false
				ipc.cond.Broadcast()
				ipc.mu.Unlock()
				return err
			}
			data = data[n:]
		}

		ipc.mu.Lock()
	}
	ipc.flushing = false
	ipc.cond.Broadcast()
	ipc.mu.Unlock()
	return nil
}

// ipcWriteTimeout is the maximum time a single conn.Write call may block.
// If the host stops reading from the socket, this prevents the enclave from
// freezing with all goroutines blocked on IPC writes.
const ipcWriteTimeout = 5 * time.Second

// writeWithDeadline sets a per-write deadline before calling conn.Write.
func (ipc *IPC) writeWithDeadline(data []byte) (int, error) {
	if c, ok := ipc.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
	}
	return ipc.conn.Write(data)
}

func varintLen(x uint64) int {
	n := 1
	for x >= 0x80 {
		x >>= 7
		n++
	}
	return n
}

// SendQueryResponse sends a query/response packet with UUID
// Used for all CmdFlagQueryResponse range packets that follow the UUID format
func (ipc *IPC) SendQueryResponse(cmd uint16, uuid []byte, data []byte) error {
	if len(uuid) != 16 {
		return fmt.Errorf("UUID must be exactly 16 bytes")
	}
	return ipc.Send(cmd, uuid, data)
}

func (ipc *IPC) Close() error {
	return ipc.conn.Close()
}

// sendToClient sends data to a client through UDP
func (ipc *IPC) sendToClient(addr *net.UDPAddr, data []byte) error {
	var header [18]byte
	copy(header[:16], addr.IP.To16())
	binary.BigEndian.PutUint16(header[16:18], uint16(addr.Port))
	return ipc.Send(CmdUDP, header[:], data)
}

func (ipc *IPC) sendToTUN(data ...[]byte) error {
	return ipc.Send(CmdTUN, data...)
}
