import json
import pygal
import os
import datetime

filename = 'statistics/data.json'
with open(filename) as f:
	datas = json.load(f)

targets = []
for x,y in datas.items():
	t1 = datetime.datetime.strptime(y[-1]['time'],'%Y-%m-%dT%H:%M:%S.%f%z')
	t2 = datetime.datetime.strptime(y[0]['time'],'%Y-%m-%dT%H:%M:%S.%f%z')
	span = t1 - t2
	print(span.total_seconds())
	if span.total_seconds() < 5:
		size = 0
		for z in y:
			size += z['len']
		targets.append((span.total_seconds(),size))

xy_chart = pygal.TimeDeltaLine(stroke = False)
xy_chart.title = 'statistics'
xy_chart.add('shortCon',targets)
if not os.path.exists('./statistics'):
	os.makedirs('./statistics')
xy_chart.render_to_file('./statistics/showShort.svg')