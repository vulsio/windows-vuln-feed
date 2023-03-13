package cmd

import (
	"compress/gzip"
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	supercedenceBuilder "github.com/vulsio/windows-vuln-feed/pkg/supercedence/builder"
	supercedenceCmd "github.com/vulsio/windows-vuln-feed/pkg/supercedence/cmd"
	supercedenceModel "github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
	vulnerabilityBuilder "github.com/vulsio/windows-vuln-feed/pkg/vulnerability/builder"
	vulnerabilityCmd "github.com/vulsio/windows-vuln-feed/pkg/vulnerability/cmd"
	vulnerabilityModel "github.com/vulsio/windows-vuln-feed/pkg/vulnerability/model"
)

// RootCmd ...
var RootCmd = &cobra.Command{
	Use:           "windows-vuln-feed",
	Short:         "Microsoft Vulnerability Feed(Vulnerability and Supercedence) Builder",
	Long:          `Microsoft Vulnerability Feed(Vulnerability and Supercedence) Builder`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch Microsoft Vulnerability Feed(Vulnerability and Supercedence)",
	Long:  "Fetch Microsoft Vulnerability Feed(Vulnerability and Supercedence)",
}

var buildCmd = &cobra.Command{
	Use:       "build",
	Short:     "Build Microsoft Vulnerability Feed(Vulnerability and Supercedence)",
	Long:      "Build Microsoft Vulnerability Feed(Vulnerability and Supercedence)",
	Example:   "windows-vuln-feed build vulnerability",
	ValidArgs: []string{"vulnerability", "supercedence"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "vulnerability":
			cves, err := vulnerabilityBuilder.Build([]string{"./dist/vulnerability/bulletin", "./dist/vulnerability/cvrf", "./dist/vulnerability/manual"})
			if err != nil {
				return errors.Wrap(err, "failed to build vulnerability")
			}
			slices.SortFunc(cves, func(i, j vulnerabilityModel.Vulnerability) bool {
				return i.CVEID < j.CVEID
			})
			for i := range cves {
				slices.SortFunc(cves[i].Products, func(i, j vulnerabilityModel.Product) bool {
					return i.ProductID < j.ProductID
				})
				for j := range cves[i].Products {
					slices.SortFunc(cves[i].Products[j].KBs, func(i, j vulnerabilityModel.KB) bool {
						return i.Article < j.Article
					})
				}
			}

			f, err := os.OpenFile("./dist/vulnerability/vulnerability.json.gz", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
			if err != nil {
				return errors.Wrap(err, "failed to open vulnerability/vulnerability.json.gz")
			}
			defer f.Close()
			w := gzip.NewWriter(f)
			defer w.Close()
			if err := json.NewEncoder(w).Encode(cves); err != nil {
				return errors.Wrap(err, "failed to encode vulnerability/vulnerability.json.gz")
			}
		case "supercedence":
			supercedences, err := supercedenceBuilder.Build([]string{"./dist/supercedence/bulletin", "./dist/supercedence/cvrf", "./dist/supercedence/wsusscn2", "./dist/supercedence/msuc", "./dist/supercedence/manual"})
			if err != nil {
				return errors.Wrap(err, "failed to build supercedence")
			}
			slices.SortFunc(supercedences, func(i, j supercedenceModel.Supercedence) bool {
				return i.KBID < j.KBID
			})
			for i := range supercedences {
				slices.Sort(supercedences[i].Supersededby.KBIDs)
			}

			f, err := os.OpenFile("./dist/supercedence/supercedence.json.gz", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
			if err != nil {
				return errors.Wrap(err, "failed to open supercedence/supercedence.json.gz")
			}
			defer f.Close()
			w := gzip.NewWriter(f)
			defer w.Close()
			if err := json.NewEncoder(w).Encode(supercedences); err != nil {
				return errors.Wrap(err, "failed to encode supercedence/supercedence.json.gz")
			}
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(fetchCmd)
	fetchCmd.AddCommand(vulnerabilityCmd.FetchVulerabilityCmd)
	fetchCmd.AddCommand(supercedenceCmd.FetchSupercedenceCmd)
	RootCmd.AddCommand(buildCmd)
}
