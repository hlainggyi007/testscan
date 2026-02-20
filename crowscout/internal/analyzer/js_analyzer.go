package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ExtractJSLinks uses subjs to find JavaScript files on a given URL
func ExtractJSLinks(url string) ([]string, error) {
	fmt.Printf("[+] Extracting JS links from %s...\n", url)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subjs", "-i", url)
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("subjs timed out for %s", url)
		}
		return nil, fmt.Errorf("subjs failed for %s: %v", url, err)
	}

	lines := strings.Split(out.String(), "\n")
	var jsLinks []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			jsLinks = append(jsLinks, line)
		}
	}
	
	return jsLinks, nil
}

// AnalyzeJS runs specific Nuclei exposure templates on the discovered JS files
func AnalyzeJS(jsURLs []string) (string, error) {
	if len(jsURLs) == 0 {
		return "", nil
	}
	
	fmt.Printf("[+] Analyzing %d JavaScript files for secrets and endpoints...\n", len(jsURLs))
	
	// Create input for nuclei
	input := strings.Join(jsURLs, "\n")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Run Nuclei with specifically the exposures tag
	cmd := exec.CommandContext(ctx, "nuclei", "-silent", "-tags", "exposure,token,key")
	cmd.Stdin = strings.NewReader(input)
	
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	if err != nil && out.Len() == 0 {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("nuclei JS analysis timed out")
		}
		return "", fmt.Errorf("nuclei JS analysis failed: %v", err)
	}

	return out.String(), nil
}
