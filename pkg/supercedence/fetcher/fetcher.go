package fetcher

import (
	"github.com/vulsio/windows-vuln-feed/pkg/supercedence/model"
)

// Fetcher ...
type Fetcher interface {
	FetchandParse() ([]model.Supercedence, error)
}
