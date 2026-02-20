package filter

import (
	"strings"
)

// CriticalPorts are ports that are always interesting
// (Removed hardcoded map, now loaded from config)

// Finding represents a single interesting result
type Finding struct {
	Source      string // e.g., "Nmap", "Nuclei"
	Description string // e.g., "Open Port 22 (SSH)", "CVE-2023-XXXX"
	Severity    string // "Info", "Low", "Medium", "High", "Critical"
}

// AnalyzeNmap parses Nmap output and returns findings
func AnalyzeNmap(output string, criticalPorts map[string]string) []Finding {
	var findings []Finding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Example line: "22/tcp open ssh"
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			parts := strings.Split(line, "/")
			port := parts[0]
			if desc, ok := criticalPorts[port]; ok {
				findings = append(findings, Finding{
					Source:      "Nmap",
					Description: "Critical Port Open: " + port + " - " + desc,
					Severity:    "High",
				})
			}
		}
	}
	return findings
}

// AnalyzeNuclei parses Nuclei output and returns findings based on requested severities
func AnalyzeNuclei(output string, severities []string) []Finding {
	var findings []Finding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Nuclei output is usually "[template-id] [protocol] [severity] URL"
		// We'll filter based on the severities list from config
		
		for _, sev := range severities {
			// Nuclei outputs severities in brackets like [critical]
			if strings.Contains(line, "["+sev+"]") {
				// Capitalize first letter for display
				displaySev := strings.ToUpper(sev[:1]) + sev[1:]
				findings = append(findings, Finding{Source: "Nuclei", Description: line, Severity: displaySev})
				break // Stop checking severities for this line once matched
			}
		}
	}
	return findings
}
