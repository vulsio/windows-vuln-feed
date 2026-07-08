// Package closeutil provides small helpers for closing io.Closers.
package closeutil

import "io"

// Quietly closes c and ignores the returned error. Use it where a Close
// failure is not actionable: read-side closers (HTTP response bodies, files
// opened for reading) and plain *os.File writes, whose write errors already
// surface at Write time. Buffered write paths (e.g. gzip.Writer) must check the
// Close error instead, because it can report a flush failure that truncates the
// output.
func Quietly(c io.Closer) {
	_ = c.Close()
}
