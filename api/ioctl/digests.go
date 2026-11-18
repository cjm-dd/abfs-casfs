// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ioctl

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	CasfsSHA256Len = 32

	casfsIocAddDigests = 3
	// addDigestsBatch bounds one ioctl; the module accepts up to 1<<24.
	addDigestsBatch = 1 << 16
)

// CasfsDigestEntry pairs a blob's git hash with the SHA-256 of its content.
type CasfsDigestEntry struct {
	Sha    [CasfsHashLen]byte
	SHA256 [CasfsSHA256Len]byte
}

type CasfsAddDigestsArgs struct {
	EntriesPtr uint64
	Count      uint32
	Processed  uint32
}

func CasfsIocAddDigests() uintptr {
	size := unsafe.Sizeof(CasfsAddDigestsArgs{})
	dir := _IOC_READ | _IOC_WRITE
	return (uintptr(dir) << _IOC_DIRSHIFT) |
		(uintptr(casfsIoctlMagic) << _IOC_TYPESHIFT) |
		(uintptr(casfsIocAddDigests) << _IOC_NRSHIFT) |
		(size << _IOC_SIZESHIFT)
}

// ErrDigestsUnsupported means the CASFS module predates the digest table.
var ErrDigestsUnsupported = errors.New("casfs module does not support digests")

// AddDigests loads known digests into the CASFS mount containing dir, a
// directory in it, so the sha256 xattr can answer for those blobs.
func AddDigests(dir string, entries []CasfsDigestEntry) error {
	if len(entries) == 0 {
		return nil
	}
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	for start := 0; start < len(entries); start += addDigestsBatch {
		batch := entries[start:min(start+addDigestsBatch, len(entries))]
		args := CasfsAddDigestsArgs{
			EntriesPtr: uint64(uintptr(unsafe.Pointer(&batch[0]))),
			Count:      uint32(len(batch)),
		}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), CasfsIocAddDigests(), uintptr(unsafe.Pointer(&args)))
		runtime.KeepAlive(batch)
		switch {
		case errno == syscall.ENOTTY:
			return ErrDigestsUnsupported
		case errno != 0:
			return fmt.Errorf("add digests ioctl on %s: %w", dir, errno)
		}
	}
	return nil
}
