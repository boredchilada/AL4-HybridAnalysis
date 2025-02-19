FROM cccs/assemblyline-v4-service-base:stable

# Set service path
ENV SERVICE_PATH hybrid_analysis.HybridAnalysis
ENV PYTHONPATH /opt/al_service

# Install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .