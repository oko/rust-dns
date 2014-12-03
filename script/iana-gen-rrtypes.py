#!/usr/bin/env python3.4

import requests
import csv
from io import StringIO

def fetch_file(url):
	rq = requests.get(url)
	print(rq.status_code)
	return StringIO(rq.content.decode(rq.encoding))

def fetch_csv(url):
	reader = csv.reader(fetch_file(url))

	return [row for row in reader][1:]

def get_rrtypes():
	data = fetch_csv("http://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv")
	rows = []
	for row in data:
		rrtype = row[0].replace('-', '').replace('*', 'STAR')
		rrnums = row[1]
		rrdesc = row[2]
		rrdscl = row[2].lower()
		if '-' in rrnums or 'obsolete' in rrdscl or 'experimental' in rrdscl:
			continue
		else:
			rows.append([rrtype, int(rrnums)])
	return rows

def gen_enum(ename, rows, rep='u16'):
	print("--------------------")

	max_size = max(map(lambda x: len(x[0]), rows))

	print("#[repr(%s)]" % rep)
	print("#[deriving(PartialEq,Show)]")
	print("pub enum %s {" % ename)

	for row in rows:
		if len(row) > 2 and row[2] != '':
			print("\n/// %s" % row[2])
		print("    %s = %s," % (row[0].ljust(max_size+1), row[1]))
	print("}")
	print("--------------------")

def gen_match_num(tname, rows, default, rep='u16'):
	print("--------------------")

	max_size = max(map(lambda x: len(str(x[1])), rows))

	print("pub fn from_%s(val: %s) -> %s {" % (rep, rep, tname))

	print("    match val {")

	for row in rows:
		print("        %s => %s::%s," % (str(row[1]).ljust(max_size+1), tname, row[0]))
	print("        _ => %s::%s," % (tname, default))
	print("}")
	print("--------------------")

def gen_match_str(tname, rows, default, rep='u16'):
	print("--------------------")

	max_size = max(map(lambda x: len(str(x[0])), rows))

	print("pub fn from_str(val: &str) -> %s {" % (tname))

	print("    match val {")

	for row in rows:
		r0 = '"%s"' % row[0]
		print('        %s => %s::%s,' % (r0.ljust(max_size+2), tname, row[0]))
	print("        _ => %s::%s," % (tname, default))
	print("}")
	print("--------------------")

def gen_test_array(rows, skip=65535,rep='u16'):
	print("[")
	for row in rows:
		if row[1] == skip:
			continue
		print("    %du16," % row[1])
	print("]")

rrtypes = get_rrtypes()
gen_enum("RRType", rrtypes)
gen_match_num("RRType", rrtypes, 'Reserved')
gen_match_str("RRType", rrtypes, 'Reserved')
gen_test_array(rrtypes)