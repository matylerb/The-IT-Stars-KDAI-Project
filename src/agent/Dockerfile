FROM python:3.11-slim

WORKDIR /app

COPY src/agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The agent imports the detector, knowledge graph, CSP and advisor from src/,
# and the knowledge graph reads its facts from data/kg/.
COPY src/ /app/src/
COPY data/kg/ /app/data/kg/

ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1
CMD ["python", "/app/src/agent/main.py"]
