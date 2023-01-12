package builder

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/util"
)

// Build ...
func Build(paths []string) ([]model.Supercedence, error) {
	supercedenceMap := map[string]model.Supercedence{}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errors.Wrapf(err, "failed to open %s", path)
		}
		defer f.Close()

		supercedences := []model.Supercedence{}
		if err := json.NewDecoder(f).Decode(&supercedences); err != nil {
			return nil, errors.Wrapf(err, "failed to decode %s", path)
		}

		for _, s := range supercedences {
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
