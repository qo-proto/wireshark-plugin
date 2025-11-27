//go:build ignore

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/qo-proto/qh"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: generate_mappings <dissector.lua>")
		os.Exit(1)
	}

	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	updated := replaceMappings(string(content), generateMappings())

	if err := os.WriteFile(os.Args[1], []byte(updated), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Mappings updated")
}

func generateMappings() string {
	var sb strings.Builder

	sb.WriteString("local qh_methods = {\n")
	for i := 0; ; i++ {
		if method := qh.Method(i).String(); method == "UNKNOWN" {
			break
		} else {
			sb.WriteString(fmt.Sprintf("    [%d] = \"%s\",\n", i, method))
		}
	}

	sb.WriteString("}\n\nlocal compact_to_status = {\n")

	codes := make([]uint8, 0, len(qh.StatusToCompact))
	for _, c := range qh.StatusToCompact {
		codes = append(codes, c)
	}

	for _, compact := range codes {
		status := qh.CompactToStatus[compact]
		sb.WriteString(fmt.Sprintf("    [%d] = %d,\n", compact, status))
	}
	sb.WriteString("}")
	return sb.String()
}

func replaceMappings(content, mappings string) string {
	const start, end = "-- BEGIN AUTO-GENERATED MAPPINGS", "-- END AUTO-GENERATED MAPPINGS"

	lines := strings.Split(content, "\n")
	var result []string
	inSection := false

	for _, line := range lines {
		if strings.Contains(line, start) {
			result = append(result, line, mappings)
			inSection = true
		} else if strings.Contains(line, end) {
			result = append(result, line)
			inSection = false
		} else if !inSection {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
