import csv, urllib, json

infile=open("users.csv", 'rb')
reader = csv.reader(infile)

outfile = open("users_geoip.py","wb")
writer = csv.writer(outfile)

data = []
url = "http://freegeoip.net/json/"
for r in reader:
	d=[]
	d.append(r[0])
	d.append(r[1])
	d.append(r[2])
	d.append(r[3])
	u = url + r[0]
	try:
		response = urllib.urlopen(u)
		j = json.loads(response.read())
		d.append(j['country_name'])
		d.append(j['city'])
		d.append(j['longitude'])
		d.append(j['latitude'])
	except Exception as e:
		print e
	data.append(d)
	print d

for d in data:
	writer.writerow(d)

f.close()
outfile.close()




