package main

import (
	"sync"
	"sync/atomic"
)

type ResponseHandler struct {
	nextID   atomic.Uint64
	handlers map[uint64]chan []byte
	mu       sync.RWMutex
}

var globalResponseHandler = &ResponseHandler{
	handlers: make(map[uint64]chan []byte),
}

// getResponseHandler allocates a new unique ID and returns a channel to listen on
func getResponseHandler() (uint64, chan []byte) {
	id := globalResponseHandler.nextID.Add(1)
	ch := make(chan []byte, 1) // buffered to avoid blocking sender

	globalResponseHandler.mu.Lock()
	globalResponseHandler.handlers[id] = ch
	globalResponseHandler.mu.Unlock()

	return id, ch
}

// sendResponseToHandler sends data to the channel associated with the given ID
// and removes it from the handlers map
func sendResponseToHandler(id uint64, data []byte) bool {
	globalResponseHandler.mu.Lock()
	ch, exists := globalResponseHandler.handlers[id]
	if exists {
		delete(globalResponseHandler.handlers, id)
	}
	globalResponseHandler.mu.Unlock()

	if !exists {
		return false
	}

	ch <- data
	return true
}
