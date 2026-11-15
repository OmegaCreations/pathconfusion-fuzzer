FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
EXPOSE 9000

# Uvicorn exposes the raw encooded path through scope["raw_path"]
#   which app.py must use to report raw_request_target faithfully.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
