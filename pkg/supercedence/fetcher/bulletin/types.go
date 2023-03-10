package bulletin

// Bulletin ...
type Bulletin struct {
	AffectedProduct   string `xlsx:"6"`
	ComponentKB       string `xlsx:"7"`
	AffectedComponent string `xlsx:"8"`
	Supersedes        string `xlsx:"11"`
}
