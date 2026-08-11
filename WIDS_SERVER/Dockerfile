FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY servidor_wids.py .

# Exponemos el puerto de la API
EXPOSE 5000

# Arrancamos Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "servidor_wids:app"]
