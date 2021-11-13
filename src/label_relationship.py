import os, json, sys
sys.path.append(r"C:\Users\Syuukakou\PycharmProjects\SCIS2022")
from src.common_functins import *
import matplotlib
import matplotlib.pyplot as plt
from collections import Counter

def label_cve_Relationship():
    cve_usage = get_CVE_Usage()
    hashes_labels = get_Hash_Label()

    labels = set()
    for h in hashes_labels:
        if not hashes_labels[h].startswith("SINGLETON"):
            labels.add(hashes_labels[h])
        else:
            labels.add("SINGLETON")
    labels = list(labels)
    print(labels)

    total_cves = []
    for h in cve_usage:
        total_cves.extend(cve_usage[h])
    total_cves = list(set(total_cves))

    total_colors = list(matplotlib.colors.cnames.keys())
    colors = total_colors[:len(total_cves)]
    cve_color = {}
    for cve_name, color in zip(total_cves, colors):
        cve_color[cve_name] = color
    
    label_hashes = {i:[] for i in labels}
    for h in hashes_labels:
        if hashes_labels[h].startswith("SINGLETON"):
            label_hashes["SINGLETON"].append(h)
        if not hashes_labels[h].startswith("SINGLETON"):
            label_hashes[hashes_labels[h]].append(h)        
    
    data = []
    for label in label_hashes:
        cves = []
        for h in label_hashes[label]:
            if h in cve_usage:
                cves.extend(cve_usage[h])
            cves_counter = dict(Counter(cves))
            for cve_name, count in cves_counter.items():
                data.append([label, cve_name, count, cve_color[cve_name]])
    
    # print(data)
    plot_labels = []
    CVE_names = []
    CVE_counts = []
    CVE_colorType = []
    for item in data:
        plot_labels.append(item[0])
        CVE_names.append(item[1])
        CVE_counts.append(item[2])
        CVE_colorType.append(item[3])
    plt.figure(figsize=(15, 15))
    plt.scatter(plot_labels, CVE_names, s=CVE_counts, alpha=0.3, edgecolors="black") #  c=CVE_colorType,
    plt.xticks(fontsize=20, rotation=30)
    plt.yticks(fontsize=10)
    plt.tight_layout()
    plt.savefig(r"files\resuls\Relationship_Between_cve_labels.png")
    # plt.show()



if __name__ == "__main__":
    label_cve_Relationship()
        
