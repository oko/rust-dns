import enumgen
from pprint import pprint
import os
import os.path

data = enumgen.fetch_csv(
	"http://www.iana.org/assignments/dns-parameters/dns-parameters-2.csv")

data_dict = []
for row in data:
	if '-' in row[0]: continue
	if ' ' in row[2]:
		row[2] = row[2].split(' ')[-1].strip('()')
	if row[2] in [i['name'] for i in data_dict]: continue
	data_dict.append({
		"name": row[2],
		"value": int(row[0]),
		"desc": row[3],
		})

print(enumgen.render_template(
	os.path.join(os.path.dirname(__file__), 'templates'),
	'enum_with_tests.rs.jinja2',
	ename='RRClass',
	rep='u16',
	default='Reserved',
	default_val=0,
	variants=data_dict,
	))