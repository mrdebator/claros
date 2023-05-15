import argparse
import collecter
from datamodels import NVDResponse
import rdf_builder
from nmap_parser import *

if __name__ == "__main__":
    print("Welcome to GraphIt!")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GraphIt")
    parser.add_argument("-c", help="CVE ID", required=False)
    parser.add_argument("-k", help="Keyword", required=False)
    parser.add_argument("-d", help="Domain Name", required=False)
    parser.add_argument("-n", help="Nmap Scan Results (XML)", required=False)
    parser.add_argument("-o", help="Ontology File", required=False)
    args = parser.parse_args()
    
    # Validate arguments
    cveID = args.c
    keyword = args.k
    domain = args.d
    nmap_file = args.n
    ontology_file = args.o

    # Check if any arguments were provided
    if not (cveID or keyword or domain or nmap_file):
        print("ERROR: No query arguments provided!")
        exit(1)

    # Create RDF graph
    if ontology_file:
        builder = rdf_builder.RDFBuilder(ontology_file)
    else:
        builder = rdf_builder.RDFBuilder()

    if cveID:
        response = collecter.query_cve(cveID)
        print("DEBUG: Total Results: " + str(response.total_results))
        for vulnerability in response.vulnerabilities:
            exploit_list = collecter.query_exploit_db(vulnerability.data.id)
            print("DEBUG: Found " + str(len(exploit_list)) + " exploits for " + vulnerability.data.id)
            builder.insert_cve_into_ontology(vuln= vulnerability.data, exploits= exploit_list)
            


    if keyword:
        response = collecter.query_keyword(keyword)
        print("DEBUG: Total Results: " + str(response.total_results))
        for vulnerability in response.vulnerabilities:
            exploit_list = collecter.query_exploit_db(vulnerability.data.id)
            print("DEBUG: Found " + str(len(exploit_list)) + " exploits for " + vulnerability.data.id)
            builder.insert_cve_into_ontology(vuln= vulnerability.data, exploits= exploit_list)

    if domain: 
        response = collecter.query_crt_sh(domain)
        for i, (key, value) in enumerate(response.items()):
            builder.insert_domain_into_ontology(key, value)

    if nmap_file:
        nmap_scan = collecter.load_nmap_scan(nmap_file)
        print("DEBUG:", nmap_scan)
        for host in nmap_scan.hosts:
            builder.insert_ip_into_ontology(host)
            print("DEBUG:", type(host))
            for port in host.ports:
                vulnerabilities = collecter.query_keyword(port.service + " " + port.version)
                builder.insert_service_into_ontology(port, vulnerabilities.vulnerabilities)
            
    # Save RDF graph
    builder.graph.serialize(destination=ontology_file, format='xml')
