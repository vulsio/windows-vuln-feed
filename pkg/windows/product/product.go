package product

import (
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	// WinDesktopPattern ...
	WinDesktopPattern = regexp.MustCompile(`(.+ on )?(Microsoft )?Windows (NT|98|20(00|03)|Millennium|XP|Vista|7|RT|8|10|11)`)
	// WinServerPattern ...
	WinServerPattern = regexp.MustCompile(`(.+ on )?(Microsoft )?Windows Server,? (20(03|08|12|16|19|22)|version)`)
)

// Format ...
func Format(pn string) string {
	if !WinDesktopPattern.MatchString(pn) && !WinServerPattern.MatchString(pn) {
		return pn
	}

	pn = strings.NewReplacer("Windows 11 for", "Windows 11 Version 21H2 for").Replace(pn)

	pns := []string{}
	caser := cases.Title(language.English)
	for _, s := range strings.Fields(pn) {
		switch lower := strings.ToLower(s); lower {
		case "version", "systems", "(server", "core":
			pns = append(pns, caser.String(lower))
		case "itanium-based":
			pns = append(pns, "Itanium-based")
		case "installation)":
			pns = append(pns, lower)
		default:
			pns = append(pns, s)
		}
	}
	return strings.Join(pns, " ")
}
