FROM python:3.11-slim

RUN useradd -m -u 1000 flaskuser

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R flaskuser:flaskuser /app
USER flaskuser
EXPOSE 5000
CMD ["python", "run.py"]