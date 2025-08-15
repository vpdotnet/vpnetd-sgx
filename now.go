package main

import (
	"sync"
	"sync/atomic"
	"time"
)

var (
	// nowVar stores the cached current time, updated every 100ms
	nowVar time.Time = time.Now()
	// nowVarLk protects concurrent access to nowVar
	nowVarLk sync.RWMutex
	// nowUint is a lock-free counter that increments approximately every second
	nowUint uint32
)

func init() {
	// Start background goroutine to update cached time values
	go nowReader()
}

// nowReader runs in the background and updates the cached time values periodically.
// This reduces the overhead of calling time.Now() frequently in hot paths.
func nowReader() {
	t := time.NewTicker(100 * time.Millisecond) // more than enough resolution for detecting old NAT entries and so on
	defer t.Stop()

	x := 0

	for now := range t.C {
		// Update the cached time value with mutex protection
		nowVarLk.Lock()
		nowVar = now
		nowVarLk.Unlock()

		x += 1
		if x >= 10 {
			// every 10 x 100ms, increment nowUint, which means nowUint increments every second, give or take
			atomic.AddUint32(&nowUint, 1)
			x = 0
		}
	}
}

// Now returns the cached current time value.
// The cached time is updated every 100ms, providing sufficient accuracy
// for most use cases while avoiding frequent system calls.
func Now() time.Time {
	nowVarLk.RLock()
	defer nowVarLk.RUnlock()

	return nowVar
}

// Now32 returns an incrementing timer (+1 per ~1 second) without using any locks.
// This is useful for operations that need a rough timestamp without the overhead
// of mutex locks, such as timeout checks or cache expiration.
func Now32() uint32 {
	return atomic.LoadUint32(&nowUint)
}
