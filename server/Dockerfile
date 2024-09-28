FROM python:3.10.15-alpine3.19

COPY . /opt/app
WORKDIR /opt/app
RUN python3 -m pip install -r requirements.txt
CMD python3 main.py
