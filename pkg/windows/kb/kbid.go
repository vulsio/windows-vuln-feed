package kb

import "regexp"

// KBIDPattern ...
var KBIDPattern = regexp.MustCompile(`\d{6,7}`)
