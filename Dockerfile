FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN sed -i "s/\u201c/\"/g; s/\u201d/\"/g; s/\u2018/'/g; s/\u2019/'/g" main.py
RUN chmod +x start.sh
CMD ["bash", "start.sh"]

