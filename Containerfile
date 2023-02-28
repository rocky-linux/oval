FROM docker.io/rockylinux:8-minimal AS base

RUN microdnf -y install python3-pip

RUN python3 -m pip install --upgrade pip

COPY . /workdir
RUN python3 -m pip install /workdir

# FROM docker.io/rockylinux:8-minimal

# COPY 

ENTRYPOINT ["oval"]
