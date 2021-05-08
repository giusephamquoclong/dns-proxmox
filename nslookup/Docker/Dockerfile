FROM python:3.9
RUN mkdir /app
COPY ../nslookup /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT python main.py