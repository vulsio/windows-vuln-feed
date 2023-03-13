package wsusscn2

type index struct {
	CABLIST struct {
		CAB []cab `xml:"CAB"`
	} `xml:"CABLIST"`
}

type cab struct {
	NAME       string `xml:"NAME,attr"`
	RANGESTART string `xml:"RANGESTART,attr"`
}

type offlineSyncPackage struct {
	Updates struct {
		Update []struct {
			UpdateID     string `xml:"UpdateId,attr"`
			RevisionID   string `xml:"RevisionId,attr"`
			IsBundle     string `xml:"IsBundle,attr"`
			IsSoftware   string `xml:"IsSoftware,attr"`
			SupersededBy struct {
				Revision []struct {
					ID string `xml:"Id,attr"`
				} `xml:"Revision"`
			} `xml:"SupersededBy"`
		} `xml:"Update"`
	} `xml:"Updates"`
}

type xKBID struct {
	KBArticleID string `xml:"KBArticleID"`
}
