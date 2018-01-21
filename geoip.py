import csv, urllib, json
import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", help="Input file name")
    parser.add_argument("outfile", help="Output file name")
    parser.add_argument("ip_column", help="Column number of ip address (first column is 0, of course)")
    parser.add_argument("num_columns", help="Total number of columns to retain in output")
    return parser.parse_args()

def main():
    args = parse_args()
    infile=open(args.infile, 'rb')
    reader = csv.reader(infile)

    outfile = open(args.outfile, 'w')
    writer = csv.writer(outfile)

    url = "http://freegeoip.net/json/"
    for r in reader:
        d=[]
        for i in range(0, int(args.num_columns)):
            d.append(r[i])
        u = url + r[int(args.ip_column)]
        try:
            response = urllib.urlopen(u)
            j = json.loads(response.read())
            d.append(j['country_name'].encode('utf-8'))
            d.append(j['city'].encode('utf-8'))
            d.append(j['longitude'])
            d.append(j['latitude'])
        except Exception as e:
            print e
        print d
        writer.writerow(d)
    infile.close()
    outfile.close()

if __name__ == "__main__":
    main()
