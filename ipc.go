package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Protocol constants are defined in protocol.go

type IPC struct {
	conn net.Conn
	wrlk sync.Mutex
	wrbf []byte
}

func NewIPC(conn net.Conn) *IPC {
	// Set socket buffer sizes to 8MB for Unix socket connection
	if unixConn, ok := conn.(*net.UnixConn); ok {
		_ = unixConn.SetReadBuffer(1024 * 1024)  // 1MB
		_ = unixConn.SetWriteBuffer(1024 * 1024) // 1MB
	}

	ipc := &IPC{
		conn: conn,
		wrbf: make([]byte, 0, SendBufferSize),
	}

	go ipc.flusher()
	return ipc
}

func (ipc *IPC) Send(cmd uint16, bufs ...[]byte) error {
	ipc.wrlk.Lock()
	defer ipc.wrlk.Unlock()

	// Use a fixed-size temporary buffer on the stack for the header
	var tmpBuf [binary.MaxVarintLen64]byte

	// Calculate total length of all buffers
	var totalLen int
	for _, buf := range bufs {
		totalLen += len(buf)
	}

	// Write command (2 bytes)
	binary.BigEndian.PutUint16(tmpBuf[:2], cmd)
	_, err := ipc.write(tmpBuf[:2])
	if err != nil {
		return err
	}

	// Write length as varint directly into the same buffer
	n := binary.PutUvarint(tmpBuf[:], uint64(totalLen))
	_, err = ipc.write(tmpBuf[:n])
	if err != nil {
		return err
	}

	// Write all the buffers sequentially
	for _, buf := range bufs {
		if len(buf) > 0 {
			_, err = ipc.write(buf)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (ipc *IPC) write(b []byte) (int, error) {
	var n int
	for {
		r := cap(ipc.wrbf) - len(ipc.wrbf)
		if len(b) <= r {
			ipc.wrbf = append(ipc.wrbf, b...)
			return n + len(b), nil
		}
		l := len(b) - r
		ipc.wrbf = append(ipc.wrbf, b[:l]...)
		b = b[l:]
		n += l

		err := ipc.flush()
		if err != nil {
			return n, err
		}
	}
}

func (ipc *IPC) Flush() error {
	ipc.wrlk.Lock()
	defer ipc.wrlk.Unlock()

	return ipc.flush()
}

func (ipc *IPC) flush() error {
	// private flush (expects lock to be already there)
	// attempt to flush all ipc.wrbf
	b := ipc.wrbf
	ipc.wrbf = ipc.wrbf[:0] // reset wrbf but keep the same buffer

	for len(b) > 0 {
		n, err := ipc.conn.Write(b)
		if err != nil {
			ipc.conn.Close() // give up on this connection
			return err
		}
		b = b[n:]
	}
	return nil
}

// SendQueryResponse sends a query/response packet with UUID
// Used for all CmdFlagQueryResponse range packets that follow the UUID format
func (ipc *IPC) SendQueryResponse(cmd uint16, uuid []byte, data []byte) error {
	// Ensure the UUID is the right length
	if len(uuid) != 16 {
		return fmt.Errorf("UUID must be exactly 16 bytes")
	}

	// Send UUID and data as separate buffers to avoid allocation
	return ipc.Send(cmd, uuid, data)
}

func (ipc *IPC) Close() error {
	return ipc.conn.Close()
}

func (ipc *IPC) flusher() {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	var err error

	for range t.C {
		if err = ipc.Flush(); err != nil {
			slog.Error("enclave: failed to write to IPC", "error", err)
			return
		}
	}
}

// sendToClient sends data to a client through UDP
func (ipc *IPC) sendToClient(addr *net.UDPAddr, data []byte) error {
	var header [18]byte
	copy(header[:16], addr.IP.To16())
	binary.BigEndian.PutUint16(header[16:18], uint16(addr.Port))

	// Send header and data as separate buffers to avoid allocation
	return ipc.Send(CmdUDP, header[:], data)
}

func (ipc *IPC) sendToTUN(data ...[]byte) error {
	return ipc.Send(CmdTUN, data...)
}
