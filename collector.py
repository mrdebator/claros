import requests
from datamodels import NVDResponse

# Query NVD for given CVE ID
def query_cves(cveID: str) -> list:
    """Query CVEs from NVD

    Args:
        cveID (str): CVE ID to query

    Returns:
        list: Results of the query
    """    
    # Run query
    baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cveFilter = "?cveId="
    url = baseURL + cveFilter + cveID
    print("DEBUG: Querying: " + url)
    response = requests.get(url)

    # Parse response
    if response.status_code == 200:
        data = NVDResponse.parse_raw(response.text)
        if data.total_results > 0:
            return [data.dict()]    
    else:
        return []


# Query NVD for given keyword
def query_keywords(keyword: str) -> list:
    # Run query
    baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keywordFilter = "?keywordSearch="
    url = baseURL + keywordFilter + keyword
    print("DEBUG: Querying: " + url)
    response = requests.get(url)

    # Parse response
    if response.status_code == 200:
        data = NVDResponse.parse_raw(response.text)
        if data.total_results > 0:
            return [data.dict()]
    else:
        return []

