FROM python:3.10-alpine as api

WORKDIR /express_alerts
COPY . .
RUN pip install -r requirements.txt --no-cache-dir