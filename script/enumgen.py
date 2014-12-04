#!/usr/bin/env python3.4

import os
import os.path

import jinja2
import requests
import csv
from io import StringIO

def fetch_file(url):
	rq = requests.get(url)
	return StringIO(rq.content.decode(rq.encoding))

def fetch_csv(url):
	reader = csv.reader(fetch_file(url))

	return [row for row in reader][1:]

def render_template(path, template, ename, rep, default, default_val, variants, with_desc=False):
	env = jinja2.Environment(loader=jinja2.FileSystemLoader(path))
	template = env.get_template(template)
	max_name_size = max([len(v['name']) for v in variants])
	max_val_size = max([len(str(v['value'])) for v in variants])

	for v in variants:
		v['name_justified'] = v['name'].ljust(max_name_size)
		v['qname_justified'] = ("%s::%s" % (ename, v['name'])).ljust(max_name_size+len(ename)+2)
		v['name_str_justified'] = ('"%s"' % v['name']).ljust(max_name_size+2)
		v['value_justified'] = str(v['value']).ljust(max_val_size)

	rc = '65536u'
	if rep == 'u8':
		rc = '256u'
	elif rep == 'u32':
		rc = '4294967296u'
	elif rep == 'u64':
		rc = '18446744073709551616u64'

	data = {
		'ename': ename,
		'default': default,
		'variants': variants,
		'rep': rep,
		'rep_ceiling': rc,
		'with_desc': with_desc,
	}
	#return data
	return template.render(**data)