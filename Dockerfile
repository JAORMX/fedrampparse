FROM registry.fedoraproject.org/fedora-minimal:latest

RUN microdnf install -y python \
    tzdata \
    python3-GitPython \
    python3-numpy \
    python3-pandas \
    python3-pyyaml \
    python3-requests \
    python3-sh \
    python3-xlrd \
    kubernetes-client

COPY fedrampread.py fedrampread.py

ENTRYPOINT ['fedrampread.py']
