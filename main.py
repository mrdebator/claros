import argparse
import collector

if __name__ == "__main__":
    print("Welcome to GraphIt!")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GraphIt")
    parser.add_argument("-c", help="CVE ID", required=False)
    parser.add_argument("-k", help="Keyword", required=False)
    parser.add_argument("-d", help="Domain Name", required=False)
    args = parser.parse_args()
    
    # Validate arguments
    cveID = args.c
    keyword = args.k
    domain = args.d

    # Check if any arguments were provided
    if not (cveID or keyword or domain):
        print("ERROR: No query arguments provided!")
        exit(1)

    if cveID:
        print(collector.query_cve(cveID))
        print(collector.query_exploit_db(cveID))
    if keyword:
        response = collector.query_keyword(keyword)
        for i in range(response.total_results):
            print(collector.query_exploit_db(response.vulnerabilities[i].data.id))

    if domain: 
        print(collector.query_crt_sh(domain))