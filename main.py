import argparse
import collector

if __name__ == "__main__":
    print("Welcome to GraphIt!")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GraphIt")
    parser.add_argument("-c", help="CVE ID", required=False)
    parser.add_argument("-k", help="Keyword", required=False)
    parser.add_argument("-d", help="Domain Name", required=False)
    parser.add_argument("-n", help="Nmap Scan Results (XML)", required=False)
    args = parser.parse_args()
    
    # Validate arguments
    cveID = args.c
    keyword = args.k
    domain = args.d
    nmap_file = args.n

    # Check if any arguments were provided
    if not (cveID or keyword or domain or nmap_file):
        print("ERROR: No query arguments provided!")
        exit(1)

    if cveID:
        print(collector.query_cve(cveID))
        print(collector.query_exploit_db(cveID))
    if keyword:
        response = collector.query_keyword(keyword)
        print(response)
        for i in range(response.total_results):
            exploit_data = collector.query_exploit_db(response.vulnerabilities[i].data.id)
            if exploit_data != []:
                print(exploit_data)
    if domain: 
        print(collector.query_crt_sh(domain))
    if nmap_file:
        testObj = collector.load_nmap_scan(nmap_file)
        print(testObj)
        print(testObj.hosts[0].ip)
