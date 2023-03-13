package msuc_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/msuc"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

func Test_parseSearch(t *testing.T) {
	tests := []struct {
		path    string
		want    []string
		wantErr bool
	}{
		{
			path: "testdata/search.html",
			want: []string{"89e09510-5a64-440a-9822-5e3d7c037266", "b983a63f-563f-42a5-b27d-bb1a41ff534c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			got, err := msuc.ParseSearch(f)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSearch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSearch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseView(t *testing.T) {
	type args struct {
		uid  string
		path string
	}
	tests := []struct {
		args    args
		want    model.Supercedence
		wantErr bool
	}{
		{
			args: args{
				uid:  "93ce66c8-6d84-40a9-b676-294bd1dcce71",
				path: "testdata/view.html",
			},
			want: model.Supercedence{
				KBID:     "5019275",
				UpdateID: "93ce66c8-6d84-40a9-b676-294bd1dcce71",
				Supersededby: &model.Supersededby{UpdateIDs: []string{
					"e81534c5-f372-49c3-a97b-d10973d170ac",
					"659771ce-b89f-4cd5-a333-196f7c6dc956",
				}},
			},
		},
		{
			args: args{
				uid:  "c45b456e-6572-4210-9185-c8d60b7798e1",
				path: "testdata/thanks.html",
			},
			want: model.Supercedence{
				KBID:         "",
				UpdateID:     "c45b456e-6572-4210-9185-c8d60b7798e1",
				Supersededby: &model.Supersededby{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.args.path, func(t *testing.T) {
			f, err := os.Open(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			got, err := msuc.ParseView(tt.args.uid, f)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseView() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseView() = %v, want %v", got, tt.want)
			}
		})
	}
}
