import enumgen
from pprint import pprint
import os
import os.path

data = enumgen.fetch_csv(
	"http://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv")

data_dict = []
for row in data:
	if '-' in row[1]: continue
	dscl = row[2].lower()
	if 'experimental' in dscl or 'obsolete' in dscl: continue
	data_dict.append({
		"name": row[0].replace('-','').replace('*', 'STAR'),
		"value": int(row[1]),
		"desc": row[2],
		})

print(enumgen.render_template(
	os.path.join(os.path.dirname(__file__), 'templates'),
	'enum_with_tests.rs.jinja2',
	ename='RRType',
	rep='u16',
	default='Reserved',
	default_val=65535,
	variants=data_dict,
	))