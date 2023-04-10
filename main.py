import argparse
import collector

if __name__ == "__main__":
    print("Welcome to GraphIt!")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GraphIt")
    parser.add_argument("-c", help="CVE ID", required=False)
    parser.add_argument("-k", help="Keyword", required=False)
    args = parser.parse_args()
    
    # Validate arguments
    cveID = args.c
    keyword = args.k

    # Check if any arguments were provided
    if not (cveID or keyword):
        print("ERROR: No query arguments provided!")
        exit(1)
    
    results = {}

    if cveID:
        # print(collector.query_cves(cveID))
        print(collector.query_exploit_db(cveID))
    if keyword:
        print(collector.query_keywords(keyword))