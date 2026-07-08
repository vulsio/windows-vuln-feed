// Package closeutil provides small helpers for closing io.Closers.
package closeutil

import "io"

// Quietly closes c, deliberately discarding the error. Use it only where the
// Close error is not actionable: read-side closers (HTTP response bodies, files
// opened for reading), and outputs whose truncation would be caught by a later
// stage (e.g. a JSON file that is re-parsed downstream).
//
// Do NOT use it when a silently truncated output would go undetected. Close can
// be the first place a deferred write error surfaces (e.g. on NFS/remote
// filesystems, or with buffered writers such as gzip.Writer), so those write
// paths must check the Close error explicitly instead.
func Quietly(c io.Closer) {
	_ = c.Close()
}
