package msuc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

// FetchandParse ...
func FetchandParse(queries []string) ([]model.Supercedence, error) {
	log.Printf("INFO: fetch MSUC. Search: %s", queries)

	var vs []model.Supercedence
	uidtoKBID := map[string]string{}
	for _, query := range queries {
		uids, err := search(query)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to search with query: "%s"`, query)
		}

		qs := uids
		for {
			if len(qs) == 0 {
				break
			}

			var next []string
			for _, uid := range qs {
				if _, ok := uidtoKBID[uid]; ok {
					continue
				}

				v, err := view(uid)
				if err != nil {
					return nil, errors.Wrapf(err, `failed to view with update id: "%s"`, uid)
				}
				if v.KBID == "" {
					log.Printf(`WARN: update id: "%s" not found KBID`, v.UpdateID)
					continue
				}
				uidtoKBID[v.UpdateID] = v.KBID
				vs = append(vs, v)
				for _, uid := range v.Supersededby.UpdateIDs {
					if _, ok := uidtoKBID[uid]; !ok {
						next = append(next, uid)
					}
				}
			}
			qs = next
		}
	}

	for i, v := range vs {
		for _, uID := range v.Supersededby.UpdateIDs {
			kb, ok := uidtoKBID[uID]
			if !ok {
				log.Printf("WARN: %s to KBID not found", uID)
				continue
			}
			v.Supersededby.KBIDs = append(v.Supersededby.KBIDs, kb)
		}
		vs[i] = v
	}

	log.Printf("INFO: %d Supercedences found", len(vs))

	return vs, nil
}

func search(query string) ([]string, error) {
	log.Printf("INFO: POST https://www.catalog.update.microsoft.com/Search.aspx?q=%s", query)

	values := url.Values{}
	values.Set("q", query)

	req, err := http.NewRequest("POST", "https://www.catalog.update.microsoft.com/Search.aspx", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to new request")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", "0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	return ParseSearch(resp.Body)
}

// ParseSearch ...
func ParseSearch(r io.Reader) ([]string, error) {
	var ids []string

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new document from reader")
	}

	doc.Find("div#tableContainer > table").Find("tr").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("id")
		if !exists || val == "headerRow" {
			return
		}
		id, _, ok := strings.Cut(val, "_")
		if !ok {
			log.Printf(`WARN: unexpected id. id="%s"`, val)
			return
		}
		ids = append(ids, id)
	})

	return ids, nil
}

func view(updateID string) (model.Supercedence, error) {
	log.Printf("INFO: GET https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=%s", updateID)

	resp, err := http.Get(fmt.Sprintf("https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=%s", updateID))
	if err != nil {
		return model.Supercedence{}, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	return ParseView(updateID, resp.Body)
}

// ParseView ...
func ParseView(updateID string, r io.Reader) (model.Supercedence, error) {
	view := model.Supercedence{UpdateID: updateID, Supersededby: &model.Supersededby{}}

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return model.Supercedence{}, errors.Wrap(err, "failed to new document from reader")
	}

	if doc.Find("body").HasClass("mainBody thanks") {
		return view, nil
	}

	_, kbid, ok := strings.Cut(strings.NewReplacer(" ", "", "\n", "").Replace(doc.Find("div#kbDiv").Text()), ":")
	if !ok {
		return model.Supercedence{}, errors.Errorf(`failed to find KBID. unexpected div#kbDiv format. expected: "...:<KBID>", actual: "%s"`, strings.NewReplacer(" ", "", "\n", "").Replace(doc.Find("div#kbDiv").Text()))
	}
	view.KBID = kbid

	doc.Find("div#supersededbyInfo > div > a").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("href")
		if !exists {
			return
		}
		if !strings.HasPrefix(val, "ScopedViewInline.aspx?updateid=") {
			log.Printf(`WARN: unexpected href. href="%s"`, val)
			return
		}
		view.Supersededby.UpdateIDs = append(view.Supersededby.UpdateIDs, strings.TrimPrefix(val, "ScopedViewInline.aspx?updateid="))
	})

	return view, nil
}
