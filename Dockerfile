ARG branch=stable
FROM cccs/assemblyline-v4-service-base:$branch

# Python path to the service class: <package>.<module>.<Class>
ENV SERVICE_PATH=hybridanalysis.service.HybridAnalysis

# System packages (as root). pkglist.txt may be empty.
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Python packages (as the unprivileged runtime user). --chown keeps the build independent of
# host file modes: a 0640 checkout would otherwise be unreadable to the assemblyline user.
USER assemblyline
COPY --chown=assemblyline:assemblyline requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && \
    rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY --chown=assemblyline:assemblyline . .

# Stamp the release version into the manifest (CCCS pattern). CI passes the git tag.
ARG version=4.7.0.dev0
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml && \
    chown -R assemblyline:assemblyline /opt/al_service

USER assemblyline
