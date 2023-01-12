package msuc

import (
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
			input: "./testdata/wsusscn2",
			expected: []model.Supercedence{
				{
					KBID:     "654321",
					UpdateID: "0a51549b-4e86-4a26-97d4-9e3567f24ea1",
					Supersededby: &model.Supersededby{
						KBIDs:     []string{"765432"},
						UpdateIDs: []string{"05a7711a-079e-4fbb-8d1a-9015c92a2ae0"},
					},
				},
				{
					KBID:     "765432",
					UpdateID: "05a7711a-079e-4fbb-8d1a-9015c92a2ae0",
					Supersededby: &model.Supersededby{
						KBIDs:     []string{"876543"},
						UpdateIDs: []string{"1c560bb8-276c-41ca-b597-35ae23bf424c"},
					},
				},
			},
		},
		// {
		// 	input:         "./testdata/error",
		// 	expectedError: true,
		// },
	}

	for i, tt := range tests {
		got, err := Parse(tt.input)
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
			cmpopts.SortSlices(func(i, j string) bool {
				return i < j
			}),
		}
		if diff := cmp.Diff(tt.expected, got, opts...); diff != "" {
			t.Errorf("[%d] failed to Parse(). (-expected +got):\n%s", i, diff)
		}
	}
}
