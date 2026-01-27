FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY templates ./templates
COPY static ./static
COPY data ./data

ENV FLASK_SECRET_KEY="change-me"

EXPOSE 5000

CMD ["python", "app.py"]
