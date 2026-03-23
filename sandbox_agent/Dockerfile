FROM python:3.11-slim

# Security: run as non-root user
RUN useradd -m -u 1001 agentuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Drop to non-root
USER agentuser

EXPOSE 5001

# No privileged mode, no NET_ADMIN capability — stub only
CMD ["python", "agent.py"]
