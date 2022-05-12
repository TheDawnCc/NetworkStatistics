import json
import pygal
import os

filename = 'data.json'
with open(filename) as f:
	datas = json.load(f)


count = 1
for x,y in datas.items():
	lens = []
	times = []

	line_chart = pygal.Line(include_x_axis=True)
	line_chart.title = 'statistics'

	for z in y:
		lens.append(z['len'])
		times.append(z['time'])

	line_chart.add(x,lens)	
	line_chart.x_labels = times
	if not os.path.exists('./statistics'):
		os.makedirs('./statistics')
	line_chart.render_to_file('./statistics/test'+str(count)+'.svg')
	count+=1