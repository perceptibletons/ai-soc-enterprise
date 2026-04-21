FROM python:3.10-slim

# Hugging Face requires a non-root user
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /app

# Copy requirement files and install
COPY --chown=user ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy all project files into the Docker container
COPY --chown=user . /app

# Streamlit MUST run on port 7860 for Hugging Face Docker spaces
CMD ["streamlit", "run", "app.py", "--server.port", "7860", "--server.address", "0.0.0.0"]
