import csv, urllib, json

infile=open("users.csv", 'rb')
reader = csv.reader(infile)

outfile = open("users_geoip.csv","wb")
writer = csv.writer(outfile)

url = "http://freegeoip.net/json/"
for r in reader:
	d=[]
	d.append(r[0])
	d.append(r[1])
	d.append(r[2])
	u = url + r[0]
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

f.close()
outfile.close()
