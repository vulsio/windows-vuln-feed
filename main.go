package main

import (
	"fmt"
	"os"

	"github.com/vulsio/windows-vuln-feed/pkg/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
