package main

import (
	"sync"
)

const (
	// Replay protection window length
	// Increased to match official WireGuard (8128 bits)
	WINDOW_SIZE = 8192 // Rounded up to next power of 2 for alignment
)

// SlidingWindow implements replay protection
type SlidingWindow struct {
	bitmap      [WINDOW_SIZE / 64]uint64
	position    uint64 // position at start of bitmap (multiple of 64)
	offset      uint64 // offset within bitmap array (ring buffer offset)
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
		sw.offset = 0
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
		// We need to move forward by at least 1 to include this counter
		diff := counter - (sw.position + WINDOW_SIZE) + 1
		// Round up to 64-bit boundary
		if n := diff % 64; n != 0 {
			diff += 64 - n
		}

		sw.position += diff

		// For large jumps, just clear the bitmap
		if diff >= WINDOW_SIZE {
			for i := range sw.bitmap {
				sw.bitmap[i] = 0
			}
			sw.offset = 0
		} else {
			// Calculate word shift
			wordShift := diff / 64
			bitmapWords := uint64(len(sw.bitmap))

			// Update offset (ring buffer wraparound)
			newOffset := (sw.offset + wordShift) % bitmapWords

			// Clear the words that are now outside the window
			// These are the words from the new end of window to the new offset
			for i := uint64(0); i < wordShift; i++ {
				sw.bitmap[(newOffset+bitmapWords-1-i)%bitmapWords] = 0
			}

			sw.offset = newOffset
		}

		// Set the bit for this counter that caused the window to move
		newPos := counter - sw.position
		newWordIndex := (sw.offset + newPos/64) % uint64(len(sw.bitmap))
		newBitIndex := newPos % 64
		sw.bitmap[newWordIndex] |= uint64(1) << newBitIndex

		// not a duplicate
		return false
	}

	// Counter is within window, check bitmap
	pos := counter - sw.position
	wordIndex := (sw.offset + pos/64) % uint64(len(sw.bitmap))
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
