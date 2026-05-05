FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TRAINER_DB_PATH=/data/trainer.sqlite3
ENV TRAINER_AUDIO_DIR=/data/audio

WORKDIR /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server ./server
COPY common ./common

RUN mkdir -p /data/audio
VOLUME ["/data"]

EXPOSE 8000
CMD ["python", "server/entrypoint.py"]
