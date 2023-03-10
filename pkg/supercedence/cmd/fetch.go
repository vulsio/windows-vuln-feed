package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/bulletin"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/cvrf"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/msuc"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/fetcher/wsusscn2"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

// FetchSupercedenceCmd ...
var FetchSupercedenceCmd = &cobra.Command{
	Use:   "supercedence",
	Short: "Fetch Microsoft Supercedenec Feed",
	Long:  "Fetch Microsoft Supercedenec Feed",
}

var fetchSupercedenceCVRFCmd = &cobra.Command{
	Use:     "cvrf",
	Short:   "Fetch Microsoft Supercedenec CVRF Feed",
	Long:    "Fetch Microsoft Supercedenec CVRF Feed",
	Example: "windows-vuln-feed fetch supercedence cvrf",
	Args:    cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		supercedences, err := cvrf.FetchandParse()
		if err != nil {
			return errors.Wrap(err, "failed to fetch and parse")
		}
		if err := os.RemoveAll("./dist/supercedence/cvrf"); err != nil {
			return errors.Wrap(err, "failed to remove supercedence/cvrf")
		}
		if err := os.MkdirAll("./dist/supercedence/cvrf", os.ModePerm); err != nil {
			return errors.Wrap(err, "failed to mkdir supercedence/cvrf")
		}
		m := map[string][]model.Supercedence{}
		for _, s := range supercedences {
			m[s.KBID] = append(m[s.KBID], s)
		}
		for kbid, ss := range m {
			if err := func() error {
				f, err := os.Create(fmt.Sprintf("./dist/supercedence/cvrf/%s.json", kbid))
				if err != nil {
					return errors.Wrapf(err, "failed to create supercedence/cvrf/%s.json", kbid)
				}
				defer f.Close()
				if err := json.NewEncoder(f).Encode(ss); err != nil {
					return errors.Wrapf(err, "failed to encode supercedence/cvrf/%s.json", kbid)
				}
				return nil
			}(); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	},
}

var fetchSupercedenceBulletinCmd = &cobra.Command{
	Use:     "bulletin",
	Short:   "Fetch Microsoft Supercedenec Bulletin Feed",
	Long:    "Fetch Microsoft Supercedenec Bulletin Feed",
	Example: "windows-vuln-feed fetch supercedence bulletin",
	Args:    cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		supercedences, err := bulletin.FetchandParse()
		if err != nil {
			return errors.Wrap(err, "failed to fetch and parse")
		}
		if err := os.RemoveAll("./dist/supercedence/bulletin"); err != nil {
			return errors.Wrap(err, "failed to remove supercedence/bulletin")
		}
		if err := os.MkdirAll("./dist/supercedence/bulletin", os.ModePerm); err != nil {
			return errors.Wrap(err, "failed to mkdir supercedence/bulletin")
		}
		m := map[string][]model.Supercedence{}
		for _, s := range supercedences {
			m[s.KBID] = append(m[s.KBID], s)
		}
		for kbid, ss := range m {
			if err := func() error {
				f, err := os.Create(fmt.Sprintf("./dist/supercedence/bulletin/%s.json", kbid))
				if err != nil {
					return errors.Wrapf(err, "failed to create supercedence/bulletin/%s.json", kbid)
				}
				defer f.Close()
				if err := json.NewEncoder(f).Encode(ss); err != nil {
					return errors.Wrapf(err, "failed to encode supercedence/bulletin/%s.json", kbid)
				}
				return nil
			}(); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	},
}

var fetchSupercedenceWsusscn2Cmd = &cobra.Command{
	Use:     "wsusscn2",
	Short:   "Fetch Microsoft Supercedenec WSUSSCN2 Feed",
	Long:    "Fetch Microsoft Supercedenec WSUSSCN2 Feed",
	Example: "windows-vuln-feed fetch supercedence wsusscn2",
	Args:    cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		supercedences, err := wsusscn2.FetchandParse()
		if err != nil {
			return errors.Wrap(err, "failed to fetch and parse")
		}
		if err := os.RemoveAll("./dist/supercedence/wsusscn2"); err != nil {
			return errors.Wrap(err, "failed to remove supercedence/wsusscn2")
		}
		if err := os.MkdirAll("./dist/supercedence/wsusscn2", os.ModePerm); err != nil {
			return errors.Wrap(err, "failed to mkdir supercedence/wsusscn2")
		}
		m := map[string][]model.Supercedence{}
		for _, s := range supercedences {
			m[s.KBID] = append(m[s.KBID], s)
		}
		for kbid, ss := range m {
			if err := func() error {
				f, err := os.Create(fmt.Sprintf("./dist/supercedence/wsusscn2/%s.json", kbid))
				if err != nil {
					return errors.Wrapf(err, "failed to create supercedence/wsusscn2/%s.json", kbid)
				}
				defer f.Close()
				if err := json.NewEncoder(f).Encode(ss); err != nil {
					return errors.Wrapf(err, "failed to encode supercedence/wsusscn2/%s.json", kbid)
				}
				return nil
			}(); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	},
}

var fetchSupercedenceMSUCCmd = &cobra.Command{
	Use:     "msuc",
	Short:   "Fetch Microsoft Supercedenec Microsoft Update Catalog Feed",
	Long:    "Fetch Microsoft Supercedenec Microsoft Update Catalog Feed",
	Example: "windows-vuln-feed fetch supercedence msuc [<search string>]",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		supercedences, err := msuc.FetchandParse(args)
		if err != nil {
			return errors.Wrap(err, "failed to fetch and parse")
		}
		if err := os.RemoveAll("./dist/supercedence/msuc"); err != nil {
			return errors.Wrap(err, "failed to remove supercedence/msuc")
		}
		if err := os.MkdirAll("./dist/supercedence/msuc", os.ModePerm); err != nil {
			return errors.Wrap(err, "failed to mkdir supercedence/msuc")
		}
		m := map[string][]model.Supercedence{}
		for _, s := range supercedences {
			m[s.KBID] = append(m[s.KBID], s)
		}
		for kbid, ss := range m {
			if err := func() error {
				f, err := os.Create(fmt.Sprintf("./dist/supercedence/msuc/%s.json", kbid))
				if err != nil {
					return errors.Wrapf(err, "failed to create supercedence/msuc/%s.json", kbid)
				}
				defer f.Close()
				if err := json.NewEncoder(f).Encode(ss); err != nil {
					return errors.Wrapf(err, "failed to encode supercedence/msuc/%s.json", kbid)
				}
				return nil
			}(); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	},
}

func init() {
	FetchSupercedenceCmd.AddCommand(fetchSupercedenceCVRFCmd, fetchSupercedenceBulletinCmd, fetchSupercedenceWsusscn2Cmd, fetchSupercedenceMSUCCmd)
}
