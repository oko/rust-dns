#!/bin/bash
CBD=$(basename $(pwd))
if [ "$CBD" != "script" ]; then
	exit 2;
fi
python gen-iana-rrtypes.py > ../src/rr/rrtype.rs
python gen-iana-rcodes.py > ../src/msg/rcode.rs
python gen-iana-opcodes.py > ../src/msg/opcode.rs