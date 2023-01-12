package model

import (
	"fmt"
)

// Supercedence ...
type Supercedence struct {
	KBID         string
	UpdateID     string        `json:",omitempty"`
	Product      string        `json:",omitempty"`
	Supersededby *Supersededby `json:",omitempty"`
}

// Supersededby ...
type Supersededby struct {
	KBIDs     []string `json:",omitempty"`
	UpdateIDs []string `json:",omitempty"`
}

// Key ...
func (s Supercedence) Key() string {
	if s.UpdateID != "" {
		return s.UpdateID
	}
	return fmt.Sprintf("%s/%s", s.KBID, s.Product)
}
