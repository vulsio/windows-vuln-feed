package builder

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

func TestBuild(t *testing.T) {
	var tests = []struct {
		in       []string
		expected []model.Supercedence
	}{
		{
			in: []string{"./testdata/data1.json", "./testdata/data2.json", "./testdata/data3.json"},
			expected: []model.Supercedence{
				{
					KBID: "0000001",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"0000002", "0000003", "0000004", "0000005"},
					},
				},
				{
					KBID: "0000002",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"0000003", "0000005"},
					},
				},
				{
					KBID: "0000003",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"0000005"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		got, err := Build(tt.in)
		if err != nil {
			t.Errorf("[%d] unexpected error has occurred. err: %s", i, err)
		}
		opts := []cmp.Option{
			cmpopts.SortSlices(func(i, j model.Supercedence) bool {
				if i.KBID == j.KBID {
					if i.UpdateID != "" || j.UpdateID != "" {
						return i.UpdateID < j.UpdateID
					}
					return i.Product < j.Product
				}
				return i.KBID < j.KBID
			}),
			cmpopts.SortSlices(func(i, j string) bool {
				return i < j
			}),
		}
		if diff := cmp.Diff(tt.expected, got, opts...); diff != "" {
			t.Errorf("[%d] failed to Build(). (-expected +got):\n%s", i, diff)
		}
	}
}
