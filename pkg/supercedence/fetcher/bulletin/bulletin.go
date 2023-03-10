package bulletin

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tealeg/xlsx"
	"golang.org/x/exp/maps"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/util"
	winkb "github.com/vulsio/windows-vuln-feed/pkg/windows/kb"
	winpro "github.com/vulsio/windows-vuln-feed/pkg/windows/product"
)

var (
	bulletinURLs = []string{
		"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
		"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch2001-2008.xlsx",
	}
)

// FetchandParse ...
func FetchandParse() ([]model.Supercedence, error) {
	log.Printf("INFO: fetch Bulletin data feeds. URL: %s", bulletinURLs)
	bulletins, err := fetch()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Bulletin data feeds")
	}

	supercedences := Parse(bulletins)
	log.Printf("INFO: %d Supercedences found", len(supercedences))

	return supercedences, nil
}

func fetch() ([]Bulletin, error) {
	bulletins := []Bulletin{}
	for _, bulletinURL := range bulletinURLs {
		req, err := http.NewRequest(http.MethodGet, bulletinURL, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to build request")
		}

		client := new(http.Client)
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "failed to do request")
		}
		defer resp.Body.Close()

		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read response body")
		}

		f, err := xlsx.OpenBinary(bs)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open xlsx binary")
		}
		for _, sheet := range f.Sheets {
			for i, row := range sheet.Rows {
				// skip header
				if i == 0 {
					continue
				}

				var line Bulletin
				if err := row.ReadStruct(&line); err != nil {
					return nil, errors.Wrap(err, "failed to read xlsx line")
				}
				bulletins = append(bulletins, line)
			}
		}
	}
	return bulletins, nil
}

// Parse ...
func Parse(bulletins []Bulletin) []model.Supercedence {
	supercedenceMap := map[string]model.Supercedence{}
	for _, bulletin := range bulletins {
		if bulletin.Supersedes == "" {
			continue
		}

		name := bulletin.AffectedProduct
		if bulletin.AffectedComponent != "" {
			if winpro.WinDesktopPattern.MatchString(bulletin.AffectedComponent) || winpro.WinServerPattern.MatchString(bulletin.AffectedComponent) {
				name = fmt.Sprintf("%s on %s", bulletin.AffectedProduct, bulletin.AffectedComponent)
			} else {
				name = fmt.Sprintf("%s on %s", bulletin.AffectedComponent, bulletin.AffectedProduct)
			}
		}

		for _, kbid := range winkb.KBIDPattern.FindAllString(bulletin.Supersedes, -1) {
			s := model.Supercedence{
				KBID:    kbid,
				Product: winpro.Format(name),
				Supersededby: &model.Supersededby{
					KBIDs: []string{bulletin.ComponentKB},
				},
			}
			key := s.Key()
			if base, ok := supercedenceMap[key]; ok {
				delete(supercedenceMap, key)
				s.Supersededby.KBIDs = util.Unique(append(s.Supersededby.KBIDs, base.Supersededby.KBIDs...))
			}
			supercedenceMap[s.Key()] = s
		}
	}
	return maps.Values(supercedenceMap)
}
