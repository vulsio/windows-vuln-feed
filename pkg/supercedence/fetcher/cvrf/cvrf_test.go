package cvrf

import (
	"encoding/xml"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		input         string
		expected      []model.Supercedence
		expectedError bool
	}{
		{
			input: "./testdata/cvrf.xml",
			expected: []model.Supercedence{
				{
					KBID:    "5012698",
					Product: "Microsoft Exchange Server 2016 Cumulative Update 22",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"5014261"},
					},
				},
				{
					KBID:    "3124280",
					Product: "Windows 8.1 for 32-bit Systems",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3192392"},
					},
				},
				{
					KBID:    "3178034",
					Product: "Windows 8.1 for 32-bit Systems",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3192392"},
					},
				},
				{
					KBID:    "3185319",
					Product: "Windows 8.1 for 32-bit Systems",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3192392"},
					},
				},
				{
					KBID:    "2849470",
					Product: "Windows Vista Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3121918"},
					},
				},
				{
					KBID:    "3181707",
					Product: "Windows Server 2008 for 32-bit Systems Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4026059"},
					},
				},
				{
					KBID:    "3203838",
					Product: "Windows Server 2008 for 32-bit Systems Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4026059"},
					},
				},
				{
					KBID:    "4014984",
					Product: "Microsoft .NET Framework 2.0 Service Pack 2 on Windows Server 2008 for Itanium-based Systems Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4019115"},
					},
				},
				{
					KBID:    "3216520",
					Product: "Microsoft .NET Framework 2.0 Service Pack 2 on Windows Server 2008 for Itanium-based Systems Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4019115"},
					},
				},
				{
					KBID:    "3142023",
					Product: "Microsoft .NET Framework 2.0 Service Pack 2 on Windows Server 2008 for Itanium-based Systems Service Pack 2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4019115"},
					},
				},
				{
					KBID:    "3118389",
					Product: "Microsoft Office 2010 Service Pack 2 (32-bit editions)",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3213636"},
					},
				},
				{
					KBID:    "4022173",
					Product: "Microsoft Office 2010 Service Pack 2 (32-bit editions)",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3213636"},
					},
				},
				{
					KBID:    "4471987",
					Product: "Microsoft .NET Framework 4.6/4.6.1/4.6.2/4.7/4.7.1/4.7.2 on Windows 7 for 32-bit Systems Service Pack 1",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4481480"},
					},
				},
				{
					KBID:    "3142037",
					Product: "Microsoft .NET Framework 4.6/4.6.1/4.6.2/4.7/4.7.1/4.7.2 on Windows 7 for 32-bit Systems Service Pack 1",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4481480"},
					},
				},
			},
		},
		{
			input:         "./testdata/error.xml",
			expectedError: true,
		},
	}

	for i, tt := range tests {
		f, err := os.Open(tt.input)
		if err != nil {
			t.Fatalf("[%d] failed to open %s. err: %s", i, tt.input, err)
		}
		defer f.Close()

		var root cvrfdoc
		if err := xml.NewDecoder(f).Decode(&root); err != nil {
			t.Fatalf("[%d] failed to decode %s. err: %s", i, tt.input, err)
		}

		got, err := Parse([]cvrfdoc{root})
		if err != nil {
			if tt.expectedError {
				continue
			}
			t.Errorf("[%d] unexpected error has occurred. err: %s", i, err)
		}
		opts := []cmp.Option{
			cmpopts.SortSlices(func(i, j model.Supercedence) bool {
				if i.KBID == j.KBID {
					return i.Product < j.Product
				}
				return i.KBID < j.KBID
			}),
		}
		if diff := cmp.Diff(tt.expected, got, opts...); diff != "" {
			t.Errorf("[%d] failed to Parse(). (-expected +got):\n%s", i, diff)
		}
	}
}
