FROM python:3.9
RUN apt update && apt install vim nano dnsutils -y
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT python main.py