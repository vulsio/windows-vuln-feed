package product

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFormatProductName(t *testing.T) {
	var tests = []struct {
		in       string
		expected string
	}{
		{
			in:       "Microsoft SQL Server 2017 for x64-based Systems",
			expected: "Microsoft SQL Server 2017 for x64-based Systems",
		},
		{
			in:       "Adobe Flash Player on Windows Server 2012",
			expected: "Adobe Flash Player on Windows Server 2012",
		},
		{
			in:       "Windows 8.1 for 32-bit systems",
			expected: "Windows 8.1 for 32-bit Systems",
		},
		{
			in:       "Windows Server 2012 R2",
			expected: "Windows Server 2012 R2",
		},
		{
			in:       "Windows Server 2022 (Server Core Installation)",
			expected: "Windows Server 2022 (Server Core installation)",
		},
		{
			in:       "Windows Server 2022  (Server Core Installation)",
			expected: "Windows Server 2022 (Server Core installation)",
		},
		{
			in:       "Windows Server 2022 (Server Core installation)",
			expected: "Windows Server 2022 (Server Core installation)",
		},
		{
			in:       "Windows Server 2022 (server core installation)",
			expected: "Windows Server 2022 (Server Core installation)",
		},
		{
			in:       "Windows 10 Version 21H2 for x64-based Systems",
			expected: "Windows 10 Version 21H2 for x64-based Systems",
		},
		{
			in:       "Windows 10 Version 21H2 for 32-bit Systems",
			expected: "Windows 10 Version 21H2 for 32-bit Systems",
		},
		{
			in:       "Windows 10 Version 1803 for ARM64-based Systems",
			expected: "Windows 10 Version 1803 for ARM64-based Systems",
		},
		{
			in:       "Windows Server 2008 for 32-bit Systems Service Pack 2",
			expected: "Windows Server 2008 for 32-bit Systems Service Pack 2",
		},
		{
			in:       "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1",
			expected: "Windows Server 2008 R2 for Itanium-based Systems Service Pack 1",
		},
		{
			in:       "Windows 11 for x64-based Systems",
			expected: "Windows 11 Version 21H2 for x64-based Systems",
		},
	}

	for i, tt := range tests {
		if diff := cmp.Diff(tt.expected, Format(tt.in)); diff != "" {
			t.Errorf("[%d] failed to Format(). (-expected +got):\n%s", i, diff)
		}
	}
}
