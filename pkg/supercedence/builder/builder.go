package builder

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/util"
)

// Build ...
func Build(dirs []string) ([]model.Supercedence, error) {
	supercedenceMap := map[string]model.Supercedence{}
	for _, dir := range dirs {
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "failed to open %s", path)
			}
			defer f.Close()

			var ss []model.Supercedence
			if err := json.NewDecoder(f).Decode(&ss); err != nil {
				return errors.Wrapf(err, "failed to decode %s", path)
			}

			for _, s := range ss {
				if base, ok := supercedenceMap[s.KBID]; ok {
					delete(supercedenceMap, s.KBID)
					s.Supersededby.KBIDs = util.Unique(append(s.Supersededby.KBIDs, base.Supersededby.KBIDs...))
				}
				if len(s.Supersededby.KBIDs) > 0 {
					supercedenceMap[s.KBID] = model.Supercedence{
						KBID: s.KBID,
						Supersededby: &model.Supersededby{
							KBIDs: s.Supersededby.KBIDs,
						},
					}
				}
			}

			return nil
		}); err != nil {
			return nil, errors.Wrap(err, "failed to walk directory")
		}
	}

	for _, s := range supercedenceMap {
		visited := map[string]struct{}{}
		for _, sKBID := range s.Supersededby.KBIDs {
			dfs(supercedenceMap, sKBID, visited)
		}
		s.Supersededby.KBIDs = maps.Keys(visited)
	}

	return maps.Values(supercedenceMap), nil
}

func dfs(m map[string]model.Supercedence, sKBID string, visited map[string]struct{}) {
	visited[sKBID] = struct{}{}
	s, ok := m[sKBID]
	if !ok {
		return
	}
	for _, s := range s.Supersededby.KBIDs {
		if _, ok := visited[s]; !ok {
			dfs(m, s, visited)
		}
	}
}
