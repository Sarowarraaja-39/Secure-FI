FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-platform.txt /app/
RUN pip install --no-cache-dir -r requirements-platform.txt && useradd --uid 10001 --create-home appuser
COPY securefi /app/securefi
COPY services /app/services
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "services.asgi:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
