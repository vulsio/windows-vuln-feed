package main

import (
	"fmt"
	"os"

	"github.com/vulsio/windows-vuln-feed/pkg/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}
