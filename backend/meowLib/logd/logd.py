"""
just makes life easier by printing everything in a log format
"""

import datetime

def logd(text_input):
    now = datetime.datetime.now()
    now = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f'[{now}] {text_input}')