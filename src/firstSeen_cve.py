import os, json, sys
from collections import Counter
sys.path.append(r"C:\Users\Syuukakou\PycharmProjects\SCIS2022")
from src.common_functins import get_CVE_Usage
import pandas as pd
import seaborn as sns
sns.set_theme(style="whitegrid")
sns.set(font='Yu Gothic')
import matplotlib.pyplot as plt

def analysis():
    folder = r"C:\Users\Syuukakou\Documents\VirusTotal_Report_PrivateAPI_56800\VirusTotal_Report"
    years = []
    years_hashes = {"before_2018": [], "from_2019": []}
    for file in os.listdir(folder):
        filepath = os.path.join(folder, file)
        if os.path.isfile(filepath):
            with open(filepath, "r") as f:
                data = json.load(f)
            md5 = data["md5"]
            first_seen_year = data["first_seen"].split("-")[0]
            # print("{} --> {}".format(md5, first_seen_year))
            years.append(first_seen_year)
            if int(first_seen_year) < 2019:
                years_hashes["before_2018"].append(md5)
            elif int(first_seen_year) >= 2019:
                years_hashes["from_2019"].append(md5)
    results = dict(sorted(Counter(years).items(), key=lambda item: int(item[0])))
    print(len(years_hashes["before_2018"]), len(years_hashes["from_2019"]))
    # with open(r"files\formatted_data\before_2018AND_from_2019.json", "w") as f:
    #     json.dump(years_hashes, f)
    return years_hashes

def year_cve_analysis():
    with open(r"files\formatted_data\before_2018AND_from_2019.json", "r") as f:
        data = json.load(f)
    cve_usage = get_CVE_Usage()
    before_2018 = []
    from_2019 = []
    h_2018 = []
    h_2019 = []
    for h in data["before_2018"]:
        if h in cve_usage and len(cve_usage[h]) > 0:
            before_2018.extend(cve_usage[h])
            h_2018.append(h)
    for h in data["from_2019"]:
        if h in cve_usage and len(cve_usage[h]) > 0:
            from_2019.extend(cve_usage[h])
            h_2019.append(h)
    statistics = {
        "2018までに登録された検体": dict(Counter(before_2018)),
        "2019以降に登録された検体": dict(Counter(from_2019))
    }
    print(len(h_2018), len(h_2019))

    plot_data = [["cve", "counts", "first_seen"]]
    all_cve = list(statistics["2018までに登録された検体"].keys())
    all_cve.extend(list(statistics["2019以降に登録された検体"].keys()))
    all_cve = list(set(all_cve))
    # print(all_cve)
    for t in statistics:
        for cve in all_cve:
            if cve in statistics[t]:
                plot_data.append([cve, statistics[t][cve], t])
            else:
                plot_data.append([cve, 0, t])

    df = pd.DataFrame(plot_data[1:], columns=plot_data[0])
    print(df)
    plt.figure(figsize=(15, 10))
    # ax = sns.barplot(data=df, x="cve", y='counts', hue='first_seen')
    ax = sns.lineplot(data=df, x="cve", y='counts', hue='first_seen')
    for p in ax.patches:
        ax.annotate("%.0f" % p.get_height(), (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=5, color='black', xytext=(0, 5),
                    textcoords='offset points', rotation=30)
    plt.legend(loc='upper right')
    plt.xticks(rotation=90, ha='left')
    plt.tight_layout()
    # plt.savefig(r"files\resuls\statistics\cve_firstSeen.png", dpi=1200)
    plt.show()


if __name__ == "__main__":
    # analysis()
    year_cve_analysis()
