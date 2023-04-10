import requests
from datamodels import NVDResponse
import pandas as pd
import io

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
    """Query Keywords from NVD

    Args:
        keyword (str): Keyword to query

    Returns:
        list: Results of the query
    """    
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

def query_exploit_db(cveID: str) -> list:
    """Query Exploit DB for given CVE ID

    Args:
        cveID (str): CVE ID to query

    Returns:
        list: Results of the query
    """    
    # Initialize CSV 
    response = requests.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")

    if response.status_code == 200:
        # Convert contents to DataFrame
        data = pd.read_csv(io.StringIO(response.content.decode('utf-8')))

        # Filter rows that contain the desired CVE ID
        cve_data = data[data['codes'].str.contains(cveID, na=False)]

        # Convert filtered DataFrame to list of dictionaries
        results = cve_data.to_dict(orient='records')
        return results
    else:
        return []