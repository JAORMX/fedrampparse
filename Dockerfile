FROM registry.fedoraproject.org/fedora-minimal:latest

RUN microdnf install -y python \
    python3-GitPython \
    python3-numpy \
    python3-pandas \
    python3-pyyaml \
    python3-requests \
    python3-sh \
    python3-xlrd \
    python3-openpyxl \
    kubernetes-client

# https://bugzilla.redhat.com/show_bug.cgi?id=1903219
RUN microdnf reinstall -y tzdata

COPY fedrampread.py /usr/bin/fedrampread.py

ENTRYPOINT ['/usr/bin/fedrampread.py']
