from bs4 import BeautifulSoup
import urllib2
import csv

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="url of web page with table in it")
    parser.add_argument("classid", help="css class name to identify the table")
    return parser.parse_args()

def main():
    args = parse_args()

    url = args.url
    html = urllib2.urlopen(url).read()
    soup = BeautifulSoup(html)
    table = soup.select_one("table."+args.classid)
    headers = [th.text.encode("utf-8") for th in table.select("tr th")]

    with open("out.csv", "w") as f:
        wr = csv.writer(f)
        wr.writerow(headers)
        wr.writerows([[td.text.encode("utf-8") for td in row.find_all("td")] for row in table.select("tr + tr")])

if __name__ == "__main__":
    main()
