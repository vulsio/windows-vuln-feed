package cvrf

import (
	"encoding/json"
	"encoding/xml"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/util"
	winkb "github.com/vulsio/windows-vuln-feed/pkg/windows/kb"
	winpro "github.com/vulsio/windows-vuln-feed/pkg/windows/product"
)

const (
	updateListURL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
)

// FetchandParse ...
func FetchandParse() ([]model.Supercedence, error) {
	log.Printf("INFO: fetch CVRF Updates. URL: %s", updateListURL)
	cvrfURLs, err := fetchCVRFURLs()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch CVRF URLs from updates")
	}

	roots, err := fetchCVRFs(cvrfURLs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch CVRF")
	}

	supercedences, err := Parse(roots)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse CVRFs")
	}

	log.Printf("INFO: %d Supercedences found", len(supercedences))

	return supercedences, nil
}

func fetchCVRFURLs() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, updateListURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build request")
	}
	req.Header.Set("Accept", "application/json")

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to do request")
	}
	defer resp.Body.Close()

	var us updates
	if err := json.NewDecoder(resp.Body).Decode(&us); err != nil {
		return nil, errors.Wrap(err, "failed to decode json")
	}

	urls := []string{}
	for _, u := range us.Value {
		uu, err := url.Parse(u.CvrfURL)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse url")
		}
		if path.Base(uu.Path) == "document" {
			continue
		}
		urls = append(urls, u.CvrfURL)
	}

	return urls, nil
}

func fetchCVRFs(cvrfURLs []string) ([]cvrfdoc, error) {
	roots := []cvrfdoc{}
	for _, cvrfURL := range cvrfURLs {
		log.Printf("INFO: fetch CVRF. URL: %s", cvrfURL)
		req, err := http.NewRequest(http.MethodGet, cvrfURL, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to build request")
		}
		req.Header.Set("Accept", "application/xml")

		client := new(http.Client)
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "failed to do request")
		}
		defer resp.Body.Close()

		var root cvrfdoc
		if err := xml.NewDecoder(resp.Body).Decode(&root); err != nil {
			return nil, errors.Wrap(err, "failed to decode xml")
		}

		roots = append(roots, root)
	}
	return roots, nil
}

// Parse ...
func Parse(roots []cvrfdoc) ([]model.Supercedence, error) {
	supercedenceMap := map[string]model.Supercedence{}

	for _, root := range roots {
		ss, err := parseVulnerability(root.Vulnerability, parseProductTree(root.ProductTree))
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse vulnerability")
		}
		for _, s := range ss {
			key := s.Key()
			if base, ok := supercedenceMap[key]; ok {
				delete(supercedenceMap, key)
				s.Supersededby.KBIDs = util.Unique(append(s.Supersededby.KBIDs, base.Supersededby.KBIDs...))
			}
			supercedenceMap[s.Key()] = s
		}
	}

	return maps.Values(supercedenceMap), nil
}

func parseProductTree(ptree productTree) map[string]string {
	products := map[string]string{}
	for _, p := range ptree.FullProductName {
		products[p.ProductID] = winpro.Format(p.Text)
	}
	return products
}

func parseVulnerability(vulns []vulnerability, ptree map[string]string) ([]model.Supercedence, error) {
	supercedenceMap := map[string]model.Supercedence{}
	for _, vuln := range vulns {
		for _, remediation := range vuln.Remediations.Remediation {
			switch remediation.Type {
			case "Vendor Fix":
				if _, err := strconv.Atoi(remediation.Description); err != nil || !winkb.KBIDPattern.MatchString(remediation.Description) {
					log.Printf("WARN: %s Description %q: does not match the KBID pattern", vuln.CVE, remediation.Description)
					break
				}

				supersedeKBIDs := winkb.KBIDPattern.FindAllString(remediation.Supercedence, -1)
				if len(supersedeKBIDs) == 0 {
					log.Printf("WARN: %s Supercedence %q: does not match the KBID pattern", vuln.CVE, remediation.Supercedence)
					break
				}

				supercedences := []model.Supercedence{}
				for _, kbid := range supersedeKBIDs {
					supercedences = append(supercedences, model.Supercedence{
						KBID: kbid,
						Supersededby: &model.Supersededby{
							KBIDs: []string{remediation.Description},
						},
					})
				}

				for _, supercedence := range supercedences {
					for _, productID := range remediation.ProductID {
						name, ok := ptree[productID]
						if !ok {
							return nil, errors.Errorf("failed to find product info for %s productID: %s", vuln.CVE, productID)
						}
						supercedence.Product = name

						key := supercedence.Key()
						if base, ok := supercedenceMap[key]; ok {
							delete(supercedenceMap, key)
							supercedence.Supersededby.KBIDs = util.Unique(append(supercedence.Supersededby.KBIDs, base.Supersededby.KBIDs...))
						}
						supercedenceMap[supercedence.Key()] = supercedence
					}
				}
			case "Known Issue", "Mitigation", "Workaround":
			default:
				log.Printf("WARN: Remediation %s: is not the type assumed.", remediation.Type)
			}
		}
	}

	supercedences := []model.Supercedence{}
	for _, s := range supercedenceMap {
		s.Supersededby.KBIDs = util.Unique(s.Supersededby.KBIDs)
		supercedences = append(supercedences, s)
	}
	return supercedences, nil
}
