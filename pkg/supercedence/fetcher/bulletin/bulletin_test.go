package bulletin

import (
	"io"
	"os"
	"testing"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tealeg/xlsx"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		input    string
		expected []model.Supercedence
	}{
		{
			input: "./testdata/BulletinSearch.xlsx",
			expected: []model.Supercedence{
				{
					KBID:    "3101746",
					Product: "Windows Server 2012 R2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"3108381", "3121212"},
					},
				},
				{
					KBID:    "4010250",
					Product: "Adobe Flash Player on Windows Server 2012 R2",
					Supersededby: &model.Supersededby{
						KBIDs: []string{"4014329"},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		f, err := os.Open(tt.input)
		if err != nil {
			t.Fatalf("[%d] failed to open %s. err: %s", i, tt.input, err)
		}
		defer f.Close()

		bs, err := io.ReadAll(f)
		if err != nil {
			t.Fatalf("[%d] failed to read %s. err: %s", i, tt.input, err)
		}

		xf, err := xlsx.OpenBinary(bs)
		if err != nil {
			t.Fatalf("[%d] failed to open xlsx. err: %s", i, err)
		}

		bulletins := []Bulletin{}
		for _, sheet := range xf.Sheets {
			for i, row := range sheet.Rows {
				// skip header
				if i == 0 {
					continue
				}

				var line Bulletin
				if err := row.ReadStruct(&line); err != nil {
					t.Fatalf("[%d] failed to read xlsx line. err: %s", i, err)
				}
				bulletins = append(bulletins, line)
			}
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
		if diff := cmp.Diff(tt.expected, Parse(bulletins), opts...); diff != "" {
			t.Errorf("[%d] failed to Parse(). (-expected +got):\n%s", i, diff)
		}
	}
}
