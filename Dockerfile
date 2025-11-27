FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server application
COPY server/ ./server/

# Create volume for secret key persistence
VOLUME /app/data

# Expose port
EXPOSE 10000

# Set environment variables
ENV SECRET_KEY_FILE=/app/data/secret_key.txt
ENV JEEDOM_URL=http://jeedom:80
ENV MAX_AGE_SECONDS=60
ENV HOST=0.0.0.0
ENV PORT=10000
ENV FLASK_ENV=production

# Run the application
CMD ["python", "-m", "server"]
