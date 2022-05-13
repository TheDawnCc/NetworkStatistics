import json
import pygal
import datetime
import os

filename = 'statistics/data.json'
with open(filename) as f:
	datas = json.load(f)

xy_chart = pygal.TimeDeltaLine(stroke = False)
xy_chart.title = 'statistics'

maxLen = []
minLen = []
avgLen = []

for x,y in datas.items():
	lst = y[:3]

	if len(lst) >= 3:
		tempLen = 0
		tempMaxLen = 0
		tempMinLen = 65535

		t1 = datetime.datetime.strptime(lst[2]['time'],'%Y-%m-%dT%H:%M:%S.%f%z')
		t2 = datetime.datetime.strptime(lst[0]['time'],'%Y-%m-%dT%H:%M:%S.%f%z')
		#time = (t1-t2)/datetime.timedelta(milliseconds=1)/1000
		time = t1-t2

		for i in lst:
			tempLen += i['len']
			if tempMaxLen < i['len']:
				tempMaxLen = i['len']
			if tempMinLen > i['len']:
				tempMinLen = i['len']
		
		tempLen = tempLen/3
		
		avgLen.append((time,tempLen))
		maxLen.append((time,tempMaxLen))
		minLen.append((time,tempMinLen))

xy_chart.add('avgLen',avgLen)
xy_chart.add('maxLen',maxLen)
xy_chart.add('minLen',minLen)
if not os.path.exists('./statistics'):
	os.makedirs('./statistics')
xy_chart.render_to_file('./statistics/establishment.svg')
