package main

import (
	"crowscout/internal/analyzer"
	"crowscout/internal/config"
	"crowscout/internal/filter"
	"crowscout/internal/runner"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	target := flag.String("t", "", "Target domain (e.g., example.com)")
	noSubfinder := flag.Bool("no-subs", false, "Skip subdomain discovery (scan only target)")
	configPath := flag.String("c", "config/config.json", "Path to config file")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: crowscout -t example.com [-c path/to/config.json]")
		os.Exit(1)
	}

	// Load Configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[-] Failed to load configuration: %v", err)
	}

	fmt.Printf("\n[+] CrowScout - Bug Hunter Edition\n")
	fmt.Printf("[+] Target: %s\n\n", *target)

	var domains []string
	if *noSubfinder {
		domains = []string{*target}
	} else {
		// 1. Run Subfinder
		fmt.Println("[*] Phase 1: Conducting Recon (Subfinder)...")
		subs, err := runner.RunSubfinder(*target)
		if err != nil {
			log.Printf("[-] Subfinder failed: %v", err)
			domains = []string{*target} // Fallback to main domain
		} else {
			fmt.Printf("[+] Found %d unique subdomains\n", len(subs))
			domains = subs
		}
	}

	// Remove arbitrary limit for real bounty hunting (or manage it via flags later)
	// We will use httpx to filter down to alive domains
	fmt.Println("\n[*] Phase 1.5: Probing Alive Targets (httpx)...")
	aliveDomains, err := runner.RunHttpx(domains)
	if err != nil {
		log.Printf("[-] Httpx failed: %v", err)
		// Fallback
		for _, d := range domains {
			aliveDomains = append(aliveDomains, runner.HttpResult{
				URL: d,
			})
		}
	}
	fmt.Printf("[+] Found %d alive subdomains out of %d\n", len(aliveDomains), len(domains))

	if len(aliveDomains) == 0 {
		fmt.Println("[-] No alive targets found. Exiting.")
		os.Exit(0)
	}

	fmt.Println("\n[*] Phase 2: Launching Concurrent Scans (Nmap + Nuclei)...")

	var wg sync.WaitGroup
	// Concurrency limit to prevent process explosion
	concurrency := 10
	sem := make(chan struct{}, concurrency)

	for _, d := range aliveDomains {
		wg.Add(1)
		sem <- struct{}{} // Acquire concurrency token
		go func(result runner.HttpResult) {
			defer wg.Done()
			defer func() { <-sem }() // Release token
			domain := result.URL

			// Construct a proper url for subsequent tools mapped to the result
			targetURL := result.URL
			if !strings.HasPrefix(targetURL, "http") {
				targetURL = "http://" + targetURL
			}
			
			// Properly parse URL to extract just the hostname (without port) for Nmap
			parsedURL, parseErr := url.Parse(targetURL)
			cleanDomain := ""
			if parseErr == nil && parsedURL.Hostname() != "" {
				cleanDomain = parsedURL.Hostname()
			} else {
				// Fallback if not a valid URL (though HttpResult should be)
				cleanDomain = strings.TrimPrefix(domain, "http://")
				cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
				cleanDomain = strings.Split(cleanDomain, ":")[0] // Strip any port manually
			}

			fmt.Printf("\n--- Scanning: %s (WAF: %v) ---\n", cleanDomain, result.IsWAF)

			// 2. Run Nmap (Skip if WAF)
			if result.IsWAF {
				fmt.Printf("[!] Skipping Nmap for %s (WAF/Cloudflare Detected)\n", cleanDomain)
			} else {
				nmapOut, err := runner.RunNmap(cleanDomain)
				if err != nil {
					log.Printf("[-] Nmap failed for %s: %v", cleanDomain, err)
				} else {
					// Analyze Nmap
					nmapFindings := filter.AnalyzeNmap(nmapOut, cfg.CriticalPorts)
					if len(nmapFindings) > 0 {
						fmt.Printf("  [!] NMAP FINDINGS FOR %s:\n", cleanDomain)
						for _, f := range nmapFindings {
							fmt.Printf("    - [%s] %s\n", f.Severity, f.Description)
						}
					}
				}
			}

			// 3. Parameter Discovery & Nuclei (Targeted Scanning)
			
			// 3a. Parameter Discovery with Arjun
			fmt.Printf("  [Arjun] Discovering parameters for %s...\n", targetURL)
			arjunOut, err := runner.RunArjun(targetURL)
			if err != nil {
				log.Printf("[-] Arjun failed for %s: %v", targetURL, err)
			} else if arjunOut != "" {
				fmt.Printf("  [!] ARJUN FOUND HIDDEN PARAMETERS FOR %s:\n%s\n", domain, arjunOut)
				// If parameters found, we could pass specific tags like sqli, xss to nuclei in production logic.
			} else {
				fmt.Printf("  [-] No hidden parameters found for %s\n", domain)
			}

			// 3b. Run Targeted Nuclei
			// Pass the IsWAF flag and TechStack to apply rate limits and smart tags
			time.Sleep(2 * time.Second)
			// Pass targetURL (with scheme) instead of cleanDomain to Nuclei to ensure HTTPS scanning correctly
			nucleiOut, err := runner.RunNuclei(targetURL, result.IsWAF, result.TechStack)
			if err != nil {
				log.Printf("[-] Nuclei failed for %s: %v", domain, err)
			} else {
				// Analyze Nuclei
				nucleiFindings := filter.AnalyzeNuclei(nucleiOut, cfg.NucleiSeverities)
				if len(nucleiFindings) > 0 {
					fmt.Printf("  [!] NUCLEI FINDINGS FOR %s:\n", domain)
					for _, f := range nucleiFindings {
						fmt.Printf("    - [%s] %s\n", f.Severity, f.Description)
					}
				} else {
					fmt.Printf("  [-] No critical vulnerabilities found by Nuclei for %s.\n", domain)
				}
			}

			// 4. JavaScript Analysis (Bug Bounty specific)
			fmt.Printf("\n  [JS] Extracting JavaScript files from %s...\n", cleanDomain)
			
			jsLinks, err := analyzer.ExtractJSLinks(targetURL)
			if err != nil {
				log.Printf("[-] Failed to extract JS for %s: %v", targetURL, err)
			} else if len(jsLinks) > 0 {
				fmt.Printf("  [JS] Found %d JavaScript files. Analyzing for secrets...\n", len(jsLinks))
				jsOut, err := analyzer.AnalyzeJS(jsLinks)
				if err != nil {
					log.Printf("[-] JS Nuclei Analysis failed for %s: %v", targetURL, err)
				} else if jsOut != "" {
						fmt.Printf("  [!] JS SECRETS FOUND FOR %s:\n%s\n", domain, jsOut)
				} else {
						fmt.Printf("  [-] No exposed secrets found in JS files for %s\n", domain)
				}
			} else {
				fmt.Printf("  [JS] No JavaScript files found for %s\n", cleanDomain)
			}
		}(d)
	}

	// Wait for all scans to complete
	wg.Wait()

	fmt.Println("\n[*] Scan Complete.")
}
