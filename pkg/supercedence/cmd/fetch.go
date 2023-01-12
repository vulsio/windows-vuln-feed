package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/bulletin"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/cvrf"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/msuc"
)

// FetchSupercedenceCmd ...
var FetchSupercedenceCmd = &cobra.Command{
	Use:       "supercedence",
	Short:     "Fetch Microsoft Supercedenec Feed",
	Long:      "Fetch Microsoft Supercedenec Feed",
	Example:   "windows-vuln-feed fetch supercedence cvrf",
	ValidArgs: []string{"cvrf", "bulletin", "msuc"},
	Args:      cobra.ExactValidArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		var fetcher fetcher.Fetcher
		switch args[0] {
		case "cvrf":
			fetcher = cvrf.Fetcher{}
		case "bulletin":
			fetcher = bulletin.Fetcher{}
		case "msuc":
			fetcher = msuc.Fetcher{}
		}
		supercedences, err := fetcher.FetchandParse()
		if err != nil {
			return errors.Wrap(err, "failed to fetch and parse")
		}
		f, err := os.OpenFile(fmt.Sprintf("./dist/supercedence/%s.json", args[0]), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
		if err != nil {
			return errors.Wrapf(err, "failed to open supercedence/%s.json", args[0])
		}
		defer f.Close()
		if err := json.NewEncoder(f).Encode(supercedences); err != nil {
			return errors.Wrapf(err, "failed to encode supercedence/%s.json", args[0])
		}
		return nil
	},
}
