#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import traceback

print("Content-Type: text/html\r\n")

try:
    QUOTES_FILE = os.path.join(os.path.dirname(__file__), 'quotes.json')
    
    with open(QUOTES_FILE, 'r', encoding='utf-8') as f:
        quotes = json.load(f)

    if not quotes or not isinstance(quotes, list):
        raise ValueError("No valid quotes found")

    header1 = f"Status: 200 OK\r\n"
    header2 = "Content-Type: application/json\r\n"
    blank_line = "\r\n"

    print(header1, end='') 
    print(header2, end='')
    print(blank_line, end='') 

    json_body = json.dumps({"quote": random.choice(quotes)})
    print(json_body)

except Exception as e:
    print(f"<h1>Error</h1><pre>{e}</pre>")
    traceback.print_exc(file=sys.stderr)
