# Demonstration only. Pin an approved base digest before production deployment.
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "-B", "app.py"]
