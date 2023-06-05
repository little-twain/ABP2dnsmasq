package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type URLContentProcessor struct {
	compiledRegexp        *regexp.Regexp
	compiledBracketRegexp *regexp.Regexp
	compiledLinkRegexp    *regexp.Regexp
}

func new_rule_processor() *URLContentProcessor {
	return &URLContentProcessor{
		compiledRegexp:        regexp.MustCompile(`^([[:punct:]]*|(https|http)*)+`),
		compiledBracketRegexp: regexp.MustCompile(`\(([^)]+)\)`),
		compiledLinkRegexp:    regexp.MustCompile(`https?://[^\s)]*gfwlist\.txt`),
	}
}

func (u *URLContentProcessor) strip_prefixes(s string, prefixes []string) string {
	for _, prefix := range prefixes {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}

func is_valid_ip(s string) bool {
	return net.ParseIP(s) != nil
}

func is_valid_proxy_address(addr string) bool {
	host, port_str, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Println("Invalid proxy address format:", err)
		return false
	}

	if host == "localhost" {
		host = "127.0.0.1"
	}

	if !is_valid_ip(host) {
		fmt.Println("Invalid IP address:", host)
		return false
	}

	port, err := strconv.Atoi(port_str)
	if err != nil || !is_valid_port(port) {
		fmt.Println("Invalid port number:", port_str)
		return false
	}

	return true
}

func handle_star_before_dot(rule string) string {
	star_position := strings.Index(rule, "*")
	dot_position := strings.Index(rule, ".")

	if star_position >= 0 && dot_position >= 0 && star_position < dot_position {
		rule = rule[dot_position+1:]
	}

	return rule
}

func handle_slash_before_star(rule string) string {
	slash_position := strings.Index(rule, "/")
	star_position := strings.Index(rule, "*")

	if slash_position > 0 && (star_position < 0 || star_position > slash_position) {
		rule = rule[:slash_position]
	}

	return rule
}

func remove_duplicates_and_ip_addresses(domains []string) []string {
	unique_domains_set := make(map[string]struct{}, len(domains))

	index := 0
	for _, domain := range domains {
		if _, exist := unique_domains_set[domain]; !exist && !is_valid_ip(domain) {
			unique_domains_set[domain] = struct{}{}
			domains[index] = domain
			index++
		}
	}

	return domains[:index]
}

func exclude_lines_without_dot(lines []string) []string {
	valid_lines := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, ".") {
			valid_lines = append(valid_lines, line)
		}
	}

	return valid_lines
}

func (u *URLContentProcessor) find_links_in_text(content string) []string {
	matches := u.compiledLinkRegexp.FindAllString(content, -1)
	return matches
}

func fetch_and_decode_content(url_string string, proxy_addr string) ([]byte, error) {
	type Result struct {
		Content []byte
		Err     error
	}

	result_ch := make(chan Result)
	var wg sync.WaitGroup
	total := 1
	if proxy_addr != "" {
		total = 2
	}
	wg.Add(total)

	fetcher := func(transport *http.Transport) {
		defer wg.Done()
		content, err := fetch_with_transport(url_string, transport)
		result_ch <- Result{Content: content, Err: err}
	}

	if proxy_addr != "" {
		go func() {
			socks5_dialer, err := proxy.SOCKS5("tcp", proxy_addr, nil, proxy.Direct)
			if err != nil {
				fmt.Println("Can't connect to the proxy via SOCKS5:", err)
			} else {
				http_transport := &http.Transport{
					Dial: socks5_dialer.Dial,
				}
				fetcher(http_transport)
			}
		}()

		go func() {
			http_proxy_url, _ := url.Parse("http://" + proxy_addr)
			http_transport := &http.Transport{
				Proxy: http.ProxyURL(http_proxy_url),
			}
			fetcher(http_transport)
		}()
	} else {
		go func() {
			http_transport := &http.Transport{}
			fetcher(http_transport)
		}()
	}

	go func() {
		wg.Wait()
		close(result_ch) // When all fetchers are done, close the channel
	}()

	// Collect results from the channel
	var last_error error
	for result := range result_ch {
		if result.Err == nil {
			return result.Content, nil
		}
		last_error = result.Err
	}

	return nil, last_error
}

func fetch_with_transport(url_string string, http_transport *http.Transport) ([]byte, error) {
	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: http_transport,
	}

	resp, err := client.Get(url_string)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func (u *URLContentProcessor) normalize_rule_line(rule string) string {
	new_line := strings.ReplaceAll(rule, "*", "/")
	new_line = strings.ReplaceAll(new_line, "\\", "")
	new_line = strings.Split(new_line, "/")[0]
	if strings.HasSuffix(new_line, ".") {
		return ""
	}
	new_line = strings.TrimPrefix(new_line, ".")
	if new_line != "" && !strings.Contains(new_line, "*") {
		return new_line
	}
	return ""
}

func (u *URLContentProcessor) transform_rules_and_domains(final_domain_list, rules, domains []string) []string {
	var wg sync.WaitGroup
	outputChannel := make(chan string, len(rules))

	for _, rule := range rules {
		wg.Add(1)
		go func(rule string) {
			defer wg.Done()

			rule = u.compiledRegexp.ReplaceAllString(rule, "")
			matches := u.compiledBracketRegexp.FindAllStringSubmatch(rule, -1)

			if len(matches) > 0 {
				for _, match := range matches {
					options := strings.Split(match[1], "|")
					for _, option := range options {
						new_line := u.normalize_rule_line(strings.Replace(rule, match[0], option, 1))
						if new_line != "" {
							outputChannel <- new_line
						}
					}
				}
			} else {
				new_line := u.normalize_rule_line(rule)
				if new_line != "" {
					outputChannel <- new_line
				}
			}
		}(rule)
	}

	go func() {
		wg.Wait()
		close(outputChannel)
	}()

	for new_line := range outputChannel {
		final_domain_list = append(final_domain_list, new_line)
	}

	final_domain_list = append(final_domain_list, domains...)
	final_domain_list = remove_duplicates_and_ip_addresses(final_domain_list)
	final_domain_list = exclude_lines_without_dot(final_domain_list)
	sort.Strings(final_domain_list)

	return final_domain_list
}

func is_valid_port(port int) bool {
	return port >= 0 && port <= 65535
}

func is_valid_ipset_name(ipset string) bool {
	matched, _ := regexp.MatchString("^[A-Za-z0-9_][A-Za-z0-9_-]{0,30}$", ipset)
	return matched
}

func main() {
	processor := new_rule_processor()

	output_file_path := flag.String("output", "", "The path of the output file")
	input_file_url := flag.String("url", "", "The URL of the file to process")
	additional_domains_file := flag.String("domain", "", "The file with additional domains to add")
	dns_server_ip := flag.String("server", "", "DNS server IP address")
	dns_server_port := flag.Int("port", 53, "DNS server port")
	ipset_name := flag.String("ipset", "", "ipset name")
	proxy_addr := flag.String("proxy", "", "proxy address")
	flag.Parse()

	if *dns_server_ip == "localhost" {
		*dns_server_ip = "127.0.0.1"
	}

	if *dns_server_ip != "" && !is_valid_ip(*dns_server_ip) {
		fmt.Println("Invalid server IP")
		os.Exit(1)
	}

	if (*dns_server_port != 53 || *ipset_name != "") && *dns_server_ip == "" {
		fmt.Println("The -server parameter is required when -port or -ipset is specified")
		os.Exit(1)
	}

	if *dns_server_ip != "" && !is_valid_port(*dns_server_port) {
		fmt.Println("Invalid port")
		os.Exit(1)
	}

	if *ipset_name != "" && !is_valid_ipset_name(*ipset_name) {
		fmt.Println("Invalid ipset name")
		os.Exit(1)
	}

	if *proxy_addr != "" && !is_valid_proxy_address(*proxy_addr) {
		fmt.Println("Invalid proxy address:", *proxy_addr)
		return
	}

	if *input_file_url == "" {
		url := "https://raw.githubusercontent.com/gfwlist/gfwlist/master/README.md"
		response, err := http.Get(url)
		if err != nil {
			fmt.Printf("Unable to get the file: %s\n", err.Error())
			fmt.Println("Consider providing a URL with the -url parameter.")
			return
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("Unable to read the content of the file: %s\n", err.Error())
			fmt.Println("Consider providing a URL with the -url parameter.")
			return
		}

		matches := processor.find_links_in_text(string(body))
		if len(matches) == 0 {
			fmt.Println("No links found in the README.md")
			fmt.Println("Consider providing a URL with the -url parameter.")
			return
		}
		*input_file_url = matches[0]
	} else {
		fmt.Printf("Using provided URL: %s\n", *input_file_url)
	}

	decoded_content, err := fetch_and_decode_content(*input_file_url, *proxy_addr)
	if err != nil {
		fmt.Printf("Unable to download and decode the file: %s\n", err.Error())
		fmt.Println("Consider providing a valid URL with the -url parameter.")
		if *proxy_addr != "" {
			fmt.Println("Also check that the proxy address is valid.")
		}
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(decoded_content)))

	rules := make([]string, 0, len(decoded_content))
	domains := make([]string, 0, len(decoded_content))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "[") {
			continue
		}
		if !strings.Contains(line, "/") && !strings.Contains(line, "*") {
			domain := strings.TrimPrefix(line, "||")
			domain = strings.TrimPrefix(domain, ".")
			if strings.Contains(domain, ":") {
				domain = strings.Split(domain, ":")[0]
			}
			if strings.Contains(domain, ".") {
				domains = append(domains, domain)
			}
		} else {
			rule := processor.strip_prefixes(line, []string{".", "||", "|http://", "|https://", "http://", "https://"})
			rule = handle_star_before_dot(rule)
			rule = handle_slash_before_star(rule)
			if strings.Contains(rule, ".") {
				rules = append(rules, rule)
			}
		}
	}

	if *additional_domains_file != "" {
		file, err := os.Open(*additional_domains_file)
		if err != nil {
			fmt.Printf("Unable to open the domain file: %s\n", err.Error())
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading domain file: %s\n", err.Error())
			return
		}
	}

	final_domain_list := make([]string, 0, len(rules)+len(domains))
	final_domain_list = processor.transform_rules_and_domains(final_domain_list, rules, domains)

	for i, domain := range final_domain_list {
		line := domain
		if *dns_server_ip != "" {
			if *dns_server_port != 0 {
				line = fmt.Sprintf("server=/%s/%s#%s", domain, *dns_server_ip, strconv.Itoa(*dns_server_port))
			} else {
				line = fmt.Sprintf("server=/%s/%s", domain, *dns_server_ip)
			}

			if *ipset_name != "" {
				line += fmt.Sprintf("\nipset=/%s/%s", domain, *ipset_name)
			}
		}
		final_domain_list[i] = line
	}

	timestamp := time.Now().Format(time.RFC3339)
	final_domain_list = append([]string{"# " + timestamp, "# " + *input_file_url}, final_domain_list...)

	file, err := os.Create(*output_file_path)
	if err != nil {
		fmt.Printf("Unable to create the output file: %s\n", err.Error())
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, line := range final_domain_list {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Printf("Unable to write to the output file: %s\n", err.Error())
			return
		}
	}

	err = writer.Flush()
	if err != nil {
		fmt.Printf("Unable to flush the buffer: %s\n", err.Error())
		return
	}
}
