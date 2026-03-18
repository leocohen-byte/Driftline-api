#!/bin/bash
python3 -c "
import re
with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()
content = content.replace('\u201c', '\"').replace('\u201d', '\"').replace('\u2018', \"'\").replace('\u2019', \"'\")
with open('main.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Quotes fixed')
"
python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
