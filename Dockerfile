FROM registry.fedoraproject.org/fedora-minimal:latest

RUN microdnf install -y python \
    python3-GitPython \
    python3-numpy \
    python3-pandas \
    python3-pyyaml \
    python3-requests \
    python3-sh \
    python3-xlrd

COPY fedrampread.py fedrampread.py

ENTRYPOINT ['fedrampread.py']