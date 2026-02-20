package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// HttpResult holds data from httpx scanning
type HttpResult struct {
	URL       string   `json:"url"`
	TechStack []string `json:"tech"`
	IsWAF     bool     // Custom flag to determine if it's protected
}

// RunSubfinder executes subfinder and returns unique subdomains
func RunSubfinder(domain string) ([]string, error) {
	fmt.Printf("[+] Running Subfinder on %s...\n", domain)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent", "-all")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("subfinder timed out")
		}
		return nil, fmt.Errorf("subfinder failed: %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	var results []string
	seen := make(map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !seen[line] {
			results = append(results, line)
			seen[line] = true
		}
	}
	return results, nil
}

// RunNmap runs a fast port scan on the target
// Returns the raw output for parsing later
func RunNmap(target string) (string, error) {
	fmt.Printf("[+] Running Nmap on %s...\n", target)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", "-T4", "-F", target)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("nmap timed out")
		}
		return "", fmt.Errorf("nmap failed: %v", err)
	}
	return out.String(), nil
}

// RunNuclei runs functionality/cve templates based on WAF and tech stack presence
func RunNuclei(target string, isWAF bool, techStack []string) (string, error) {
	fmt.Printf("[+] Running Smart Nuclei on %s...\n", target)
	
	// Base nuclei command
	args := []string{"-u", target, "-silent"}

	// Determine smart tags based on technology fingerprint
	var tags []string
	
	for _, tech := range techStack {
		techLower := strings.ToLower(tech)
		if strings.Contains(techLower, "wordpress") {
			tags = append(tags, "wordpress")
		} else if strings.Contains(techLower, "php") {
			tags = append(tags, "php")
		} else if strings.Contains(techLower, "react") || strings.Contains(techLower, "vue") || strings.Contains(techLower, "angular") {
			tags = append(tags, "xss", "exposure")
		} else if strings.Contains(techLower, "mysql") || strings.Contains(techLower, "postgresql") {
			tags = append(tags, "sqli")
		}
	}

	// Always include generic high-value tags unless specifically skipped
	tags = append(tags, "cve", "misconfig", "exposure")

	// If protected by WAF/Cloudflare, throttle and limit scope to the safest tags
	if isWAF {
		fmt.Printf("[!] WAF detected for %s - Throttling Nuclei to evade detection...\n", target)
		// Rate limit to 10 requests / sec
		args = append(args, "-rl", "10")
		// Force override tags to be safe
		tags = []string{"cve", "misconfig", "exposure"} 
	} else {
		// Non-WAF targets get a slightly faster scan but we still add the smart tags
		args = append(args, "-rl", "50")
	}

	// Join all unique tags
	args = append(args, "-tags", strings.Join(tags, ","))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("nuclei timed out")
		}
		return "", fmt.Errorf("nuclei failed: %v", err)
	}
	return out.String(), nil
}

// RunHttpx runs httpx to probe for alive domains and returns valid HttpResults
func RunHttpx(domains []string) ([]HttpResult, error) {
	fmt.Printf("[+] Running httpx on %d domains to find alive targets and fingerprint WAF...\n", len(domains))
	
	// Create input for httpx
	input := strings.Join(domains, "\n")
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Call httpx with JSON output and technology detection enabled
	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-json", "-tech-detect")
	cmd.Stdin = strings.NewReader(input)
	
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("httpx timed out")
		}
		if out.Len() == 0 {
			return nil, fmt.Errorf("httpx failed: %v", err)
		} else {
			fmt.Printf("[!] Warning: httpx completed with errors but returned partial results: %v\n", err)
		}
	}

	lines := strings.Split(out.String(), "\n")
	var results []HttpResult
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var res HttpResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue // Skip lines we can't parse
		}

		// Determine if WAF is present based on technology stack
		res.IsWAF = false
		for _, tech := range res.TechStack {
			techLower := strings.ToLower(tech)
			if strings.Contains(techLower, "cloudflare") || 
			   strings.Contains(techLower, "akamai") || 
			   strings.Contains(techLower, "incapsula") || 
			   strings.Contains(techLower, "sucuri") {
				res.IsWAF = true
				break
			}
		}

		results = append(results, res)
	}
	return results, nil
}

// RunArjun runs the parameter discovery tool Arjun on a specific URL
func RunArjun(url string) (string, error) {
	fmt.Printf("[+] Running Arjun parameter discovery on %s...\n", url)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arjun", "-u", url, "-q", "-t", "5")
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	if err != nil && out.Len() == 0 {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("arjun timed out")
		}
		return "", fmt.Errorf("arjun failed or found no params: %v", err)
	}

	result := strings.TrimSpace(out.String())
	if result == "" {
		return "", nil // No parameters found
	}
	
	return result, nil
}
