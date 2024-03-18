FROM nexus.privatehost.com:8442/python:3.11

WORKDIR /backend

COPY requirements.txt /backend/
RUN pip install -r requirements.txt
COPY . /backend/


CMD ["jupyter", "lab", "--port=8888", "--no-browser", "--ip=0.0.0.0", "--allow-root"]

# docker build --rm --tag=nexus.privatehost.com:8444/orgname/snoozeweb/snooze_migrate:latest .