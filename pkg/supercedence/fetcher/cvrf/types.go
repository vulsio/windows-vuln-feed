package cvrf

type updates struct {
	Value []struct {
		CvrfURL string `json:"CvrfUrl"`
	} `json:"value"`
}

type cvrfdoc struct {
	ProductTree   productTree     `xml:"ProductTree"`
	Vulnerability []vulnerability `xml:"Vulnerability"`
}

type productTree struct {
	FullProductName []struct {
		Text      string `xml:",chardata"`
		ProductID string `xml:"ProductID,attr"`
	} `xml:"FullProductName"`
}

type vulnerability struct {
	CVE          string `xml:"CVE"`
	Remediations struct {
		Remediation []struct {
			Type         string   `xml:"Type,attr"`
			Description  string   `xml:"Description"`
			Supercedence string   `xml:"Supercedence"`
			ProductID    []string `xml:"ProductID"`
		} `xml:"Remediation"`
	} `xml:"Remediations"`
}
