import enumgen
from pprint import pprint
import os
import os.path

data = enumgen.fetch_csv(
	"http://www.iana.org/assignments/dns-parameters/dns-parameters-6.csv")

data_dict = []
for row in data:
	if '-' in row[0]: continue
	if int(row[0]) in [x['value'] for x in data_dict]:
		continue
	if ' ' in row[1]:
		row[1] = row[1].split(' ')[0]
		import re, string; pattern = re.compile('[\W_]+')
		row[1] = pattern.sub('', row[1])
	data_dict.append({
		"name": row[1],
		"value": int(row[0]),
		"desc": row[2],
		})

print(enumgen.render_template(
	os.path.join(os.path.dirname(__file__), 'templates'),
	'enum_with_tests.rs.jinja2',
	ename='RCode',
	rep='u16',
	default='Reserved',
	default_val=65535,
	variants=data_dict,
	with_desc=True,
	))