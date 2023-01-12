# windows-vuln-feed

## Usage
```console
$ make install

$ windows-vuln-feed --help
Microsoft Vulnerability Feed(Vulnerability and Supercedence) Builder

Usage:
  windows-vuln-feed [command]

Available Commands:
  build       Build Microsoft Vulnerability Feed(Vulnerability and Supercedence)
  completion  Generate the autocompletion script for the specified shell
  fetch       Fetch Microsoft Vulnerability Feed(Vulnerability and Supercedence)
  help        Help about any command

Flags:
  -h, --help   help for windows-vuln-feed

Use "windows-vuln-feed [command] --help" for more information about a command.
```

### For Vulnerability
```console
$ windows-vuln-feed fetch vulnerability cvrf
$ windows-vuln-feed build vulnerability
```

### Fetch Supercedence
```console
$ windows-vuln-feed fetch supercedence cvrf
$ windows-vuln-feed build supercedence
```
