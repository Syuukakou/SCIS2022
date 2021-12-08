import json

def test():
    with open(r"files\formatted_data\cve_usage.json", "r") as f:
        data = json.load(f)
    count = 0
    for h in data:
        if len(data[h]) != 0:
            count += 1
    print(count)

if __name__ == "__main__":
    test()