import sys, json
sys.path.append(r"C:\Users\Syuukakou\PycharmProjects\SCIS2022")

def get_CVE_Usage():
    with open(r"files\formatted_data\cve_usage.json", "r") as f:
        cve_usage = json.load(f)
    return cve_usage

def get_hashes_architecture():
    with open(r"files\formatted_data\hashcode_architecture.json", "r") as f:
        hashes_archi = json.load(f)
    return hashes_archi

def get_Architectures_hashes():
    with open(r"files\formatted_data\architectures_hashcodes_dict.json", "r") as f:
        archi_hashes = json.load(f)
    return archi_hashes

def get_Hash_Label():
    with open(r"files\formatted_data\hashes_labels.json", "r") as f:
        hashes_labels = json.load(f)
    return hashes_labels