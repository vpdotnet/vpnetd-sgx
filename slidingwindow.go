package main

import (
	"sync"
)

const (
	// Replay protection window length
	WINDOW_SIZE = 2048
)

// SlidingWindow implements replay protection
type SlidingWindow struct {
	bitmap      [WINDOW_SIZE / 64]uint64
	position    uint64 // position at start of bitmap (multiple of 64)
	mutex       sync.Mutex
	initialized bool
}

// CheckReplay checks if a packet is a replay
func (sw *SlidingWindow) CheckReplay(counter uint64) bool {
	// Lock mutex
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	// Special handling for first packet after Reset
	if !sw.initialized {
		sw.position = counter - (counter % 64)
		sw.initialized = true
		for n := range sw.bitmap {
			sw.bitmap[n] = 0
		}
		// continue through normal process to mark packet as received
	}

	// If counter is too old, it's a replay
	if counter < sw.position {
		return true
	}

	// If counter is outside our sliding window, move it forward
	if counter >= sw.position+WINDOW_SIZE {
		// Calculate how many bits to shift
		diff := counter - (sw.position + WINDOW_SIZE)
		if n := diff % 64; n != 0 {
			// round up to 64
			diff += 64 - n
		}

		sw.position += diff

		// For large jumps, just clear the bitmap
		if diff >= WINDOW_SIZE {
			for i := range sw.bitmap {
				sw.bitmap[i] = 0
			}
		} else {
			// Shift bitmap by word-aligned amount
			wordShift := diff / 64

			// Move existing bitmap entries backwards (towards 0)
			copy(sw.bitmap[:], sw.bitmap[wordShift:])

			// Clear the new positions at the end
			for i := uint64(len(sw.bitmap)) - wordShift; i < uint64(len(sw.bitmap)); i++ {
				sw.bitmap[i] = 0
			}
		}

		// not a duplicate
		return false
	}

	// Counter is within window, check bitmap
	pos := counter - sw.position
	wordIndex := pos / 64
	bitIndex := pos % 64

	// Check if bit is already set
	mask := uint64(1) << bitIndex
	if (sw.bitmap[wordIndex] & mask) != 0 {
		return true
	}

	// Set bit for this counter
	sw.bitmap[wordIndex] |= mask
	return false
}

// Reset resets the sliding window
func (sw *SlidingWindow) Reset() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	sw.initialized = false // Mark as not initialized
}
