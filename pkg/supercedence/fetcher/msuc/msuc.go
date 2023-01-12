package msuc

import (
	"context"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

var (
	wsusscnURL  = "http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"
	concurrency = 2
)

// FetchandParse ...
func (f Fetcher) FetchandParse() ([]model.Supercedence, error) {
	log.Printf("INFO: fetch wsusscn2.cab by %s", wsusscnURL)
	cabDir, err := fetchWSUSSCN()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch wsusscn2.cab")
	}

	supercedences, err := Parse(cabDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse wsusscn2.cab")
	}

	if err := os.RemoveAll(cabDir); err != nil {
		return nil, errors.Wrapf(err, "failed to remove %s", cabDir)
	}

	log.Printf("INFO: %d Supercedences found", len(supercedences))

	return supercedences, nil
}

func fetchWSUSSCN() (string, error) {
	dir, err := os.MkdirTemp("", "windows-vuln-feed")
	if err != nil {
		return "", errors.Wrap(err, "failed to make directory")
	}

	req, err := http.NewRequest(http.MethodGet, wsusscnURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to build request")
	}

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to do request")
	}
	defer resp.Body.Close()

	f, err := os.Create(filepath.Join(dir, "wsusscn2.cab"))
	if err != nil {
		return "", errors.Wrap(err, "failed to create wsusscn2.cab")
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", errors.Wrap(err, "failed to copy to wsusscn2.cab from response body")
	}

	if err := extractWSUSSCN(dir); err != nil {
		return "", errors.Wrap(err, "failed to extract wsusscn2.cab")
	}

	return filepath.Join(dir, "wsusscn2"), nil
}

func extractWSUSSCN(tmpDir string) error {
	binPath, err := exec.LookPath("cabextract")
	if err != nil {
		return errors.Wrap(err, "failed to look cabextract path")
	}

	log.Printf("INFO: extract %s", filepath.Join(tmpDir, "wsusscn2.cab"))
	if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2"), filepath.Join(tmpDir, "wsusscn2.cab")).Run(); err != nil {
		return errors.Wrap(err, "failed to run cabextract wsusscn2.cab")
	}
	if err := os.Remove(filepath.Join(tmpDir, "wsusscn2.cab")); err != nil {
		return errors.Wrap(err, "failed to remove wsusscn2.cab")
	}

	f, err := os.Open(filepath.Join(tmpDir, "wsusscn2", "index.xml"))
	if err != nil {
		return errors.Wrap(err, "failed to open wsusscn2/index.xml")
	}
	defer f.Close()

	var cabIndex index
	if err := xml.NewDecoder(f).Decode(&cabIndex); err != nil {
		return errors.Wrap(err, "failed to decode xml")
	}

	log.Printf("INFO: extract %s", filepath.Join(tmpDir, "wsusscn2", "package.cab"))
	if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2", "package"), filepath.Join(tmpDir, "wsusscn2", "package.cab")).Run(); err != nil {
		return errors.Wrap(err, "failed to run cabextract wsusscn2/package.cab")
	}
	if err := os.Remove(filepath.Join(tmpDir, "wsusscn2", "package.cab")); err != nil {
		return errors.Wrap(err, "failed to remove wsusscn2/package.cab")
	}

	log.Printf("INFO: extract %s", filepath.Join(tmpDir, "wsusscn2", "package\\d{1,2}.cab"))
	bar := pb.StartNew(len(cabIndex.CABLIST.CAB) - 1)
	eg, ctx := errgroup.WithContext(context.Background())
	sem := semaphore.NewWeighted(int64(concurrency))
	for _, c := range cabIndex.CABLIST.CAB {
		c := c
		eg.Go(func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return errors.Wrap(err, "failed to acquire semaphore")
			}
			defer sem.Release(1)

			if c.NAME == "package.cab" {
				return nil
			}

			if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab")), filepath.Join(tmpDir, "wsusscn2", c.NAME)).Run(); err != nil {
				return errors.Wrapf(err, "failed to cabextract wsusscn2/%s", c.NAME)
			}
			if err := os.Remove(filepath.Join(tmpDir, "wsusscn2", c.NAME)); err != nil {
				return errors.Wrapf(err, "failed to remove wsusscn2/%s", c.NAME)
			}

			dirs, err := os.ReadDir(filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab")))
			if err != nil {
				return errors.Wrapf(err, "failed to read wsusscn2/%s", strings.TrimSuffix(c.NAME, ".cab"))
			}
			for _, dir := range dirs {
				if filepath.Base(dir.Name()) == "x" {
					continue
				}
				if err := os.RemoveAll(filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())); err != nil {
					return errors.Wrapf(err, "failed to remove wsusscn2/%s/%s", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())
				}
			}

			bar.Increment()

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrapf(err, "failed to extract %s", filepath.Join(tmpDir, "wsusscn2", "package\\d{1,2}.cab"))
	}
	bar.Finish()

	return nil
}

// Parse ...
func Parse(cabDir string) ([]model.Supercedence, error) {
	rIDtoUID, supersededbyRID, err := walkPackage(filepath.Join(cabDir, "package", "package.xml"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to walk wsusscn2/package/package.xml")
	}

	rIDtoKBID, err := walkXDirs(cabDir, maps.Keys(rIDtoUID))
	if err != nil {
		return nil, errors.Wrap(err, "failed to walk wsusscn2/package\\d{1,2}/x/<Revision ID>")
	}

	rivisions := []model.Supercedence{}
	for rid, supersededby := range supersededbyRID {
		r := model.Supercedence{
			UpdateID: rid,
			Supersededby: &model.Supersededby{
				UpdateIDs: []string{},
			},
		}
		for _, srid := range supersededby {
			r.Supersededby.UpdateIDs = append(r.Supersededby.UpdateIDs, srid)
		}
		rivisions = append(rivisions, r)
	}

	supercedences := []model.Supercedence{}
	for _, r := range rivisions {
		s := model.Supercedence{
			KBID:     rIDtoKBID[r.UpdateID],
			UpdateID: rIDtoUID[r.UpdateID],
			Supersededby: &model.Supersededby{
				KBIDs:     []string{},
				UpdateIDs: []string{},
			},
		}
		for _, ruid := range r.Supersededby.UpdateIDs {
			if _, ok := rIDtoKBID[ruid]; ok {
				s.Supersededby.KBIDs = append(s.Supersededby.KBIDs, rIDtoKBID[ruid])
			}
			if _, ok := rIDtoUID[ruid]; ok {
				s.Supersededby.UpdateIDs = append(s.Supersededby.UpdateIDs, rIDtoUID[ruid])
			}
		}
		supercedences = append(supercedences, s)
	}
	return supercedences, nil
}

func walkPackage(packagePath string) (map[string]string, map[string][]string, error) {
	f, err := os.Open(packagePath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open package.xml")
	}
	defer f.Close()

	var packages offlineSyncPackage
	if err := xml.NewDecoder(f).Decode(&packages); err != nil {
		return nil, nil, errors.Wrap(err, "failed to decode package.xml")
	}

	rIDtoUID := map[string]string{}
	supersededbyRID := map[string][]string{}
	for _, u := range packages.Updates.Update {
		if u.IsBundle != "true" || u.IsSoftware == "false" {
			continue
		}
		rIDtoUID[u.RevisionID] = u.UpdateID
		for _, sr := range u.SupersededBy.Revision {
			supersededbyRID[u.RevisionID] = append(supersededbyRID[u.RevisionID], sr.ID)
		}
	}
	return rIDtoUID, supersededbyRID, nil
}

func walkXDirs(cabDir string, rids []string) (map[string]string, error) {
	f, err := os.Open(filepath.Join(cabDir, "index.xml"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to open wsusscn2/index.xml")
	}
	defer f.Close()

	var cabIndex index
	if err := xml.NewDecoder(f).Decode(&cabIndex); err != nil {
		return nil, errors.Wrap(err, "failed to decode xml")
	}
	cabs := []cab{}
	for _, c := range cabIndex.CABLIST.CAB {
		if c.RANGESTART == "" {
			continue
		}
		cabs = append(cabs, c)
	}
	slices.SortFunc(cabs, func(i, j cab) bool {
		iint, _ := strconv.ParseInt(i.RANGESTART, 10, 32)
		jint, _ := strconv.ParseInt(j.RANGESTART, 10, 32)
		return iint > jint
	})

	rIDtoKBID := map[string]string{}
	for _, rid := range rids {
		kbid, err := getKBID(rid, cabDir, cabs)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get KBID")
		}
		rIDtoKBID[rid] = kbid
	}
	return rIDtoKBID, nil
}

func getKBID(rid, cabDir string, cabs []cab) (string, error) {
	ridint, err := strconv.ParseUint(rid, 10, 32)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse uint")
	}

	for _, c := range cabs {
		cabint, err := strconv.ParseUint(c.RANGESTART, 10, 32)
		if err != nil {
			return "", errors.Wrap(err, "failed to parse uint")
		}

		if ridint < cabint {
			continue
		}

		f, err := os.Open(filepath.Join(cabDir, strings.TrimSuffix(c.NAME, ".cab"), "x", rid))
		if err != nil {
			return "", errors.Wrapf(err, "failed to open wsusscn2/%s/x/%s", strings.TrimSuffix(c.NAME, ".cab"), rid)
		}
		defer f.Close()

		var xKBID xKBID
		if err := xml.NewDecoder(f).Decode(&xKBID); err != nil {
			return "", errors.Wrap(err, "failed to decode xml")
		}
		return xKBID.KBArticleID, nil
	}
	return "", errors.Errorf("failed to find cab directory for revision id %s", rid)
}
