import json
import pygal
import os

from pygal.graph.line import Line

filename = 'statistics/count.json'
with open(filename) as f:
    datas = json.load(f)

time = []
count = []

for i,j in datas.items():
    time.append(i)
    count.append(j)

line_chart = pygal.Line(include_x_axis=True)
line_chart.title = 'statistics'

line_chart.add('Count',count)
line_chart.x_labels = time

if not os.path.exists('./statistics'):
    os.makedirs('./statistics')

line_chart.render_to_file('./statistics/count.svg')