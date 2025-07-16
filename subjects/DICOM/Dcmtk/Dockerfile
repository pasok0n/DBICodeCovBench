FROM ubuntu:24.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    libssl-dev \
    clang \
    cmake \
    git \
    autoconf \
    python3 \ 
    python3-venv \
    python3-pip \
    nano \
    gdb \
    strace \
    wget \
    libcap-dev

# Add a new user ubuntu, pass: ubuntu
RUN getent group ubuntu || groupadd ubuntu && \
    id -u ubuntu &>/dev/null || useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"


# Use ubuntu as default username
USER ubuntu
WORKDIR /home/ubuntu

# Import environment variable to pass as parameter to make (e.g., to make parallel builds with -j)
ARG MAKE_OPT

# Set up environment variables
ENV WORKDIR="/home/ubuntu/experiments"
ENV DYNAMORIO="/home/ubuntu/dynamorio"
ENV PIN="/home/ubuntu/pin/"

#Set up DBI tools

#DynamoRIO
RUN wget https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Linux-11.3.0.tar.gz && \
    tar -xzf DynamoRIO-Linux-11.3.0.tar.gz && \
    rm DynamoRIO-Linux-11.3.0.tar.gz && \
    mv DynamoRIO-Linux-* dynamorio

#Pin 
RUN wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    tar -xzf pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    rm pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    mv pin-external-3.31-98869-gfa6f126a8-gcc-linux pin

#Frida
RUN python3 -m venv /home/ubuntu/venv
ENV PATH="/home/ubuntu/venv/bin:$PATH"
COPY --chown=ubuntu:ubuntu tools/frida.patch ${WORKDIR}/frida.patch
RUN pip install --upgrade pip && pip install frida-tools==13.7.1 && \
    cd $WORKDIR && \
    wget https://raw.githubusercontent.com/gaasedelen/lighthouse/refs/heads/master/coverage/frida/frida-drcov.py && \
    patch -p1 frida-drcov.py < frida.patch

#Boofuzz
RUN pip install boofuzz

# Copying needed files
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/run.sh
COPY --chown=ubuntu:ubuntu tools/drcov_inject.sh ${WORKDIR}/drcov_inject.sh
COPY --chown=ubuntu:ubuntu tools/drcov_spawn.sh ${WORKDIR}/drcov_spawn.sh
COPY --chown=ubuntu:ubuntu tools/run_pin.sh ${WORKDIR}/run_pin.sh
COPY --chown=ubuntu:ubuntu tools/pin_cov.cpp ${PIN}/source/tools/MyPinTool/pin_cov.cpp
COPY --chown=ubuntu:ubuntu dicom_fuzz.py ${WORKDIR}/dicom_fuzz.py
COPY --chown=ubuntu:ubuntu tools/frida-spawn.py ${WORKDIR}/frida-spawn.py

# Compiling Pin Coverage
RUN cd $PIN/source/tools/MyPinTool && \
    mkdir obj-intel64 && \
    make obj-intel64/pin_cov.so


USER root

# Download and compile Dcmtk
RUN cd $WORKDIR && \
    git clone https://github.com/DCMTK/dcmtk && \
    cd dcmtk && \
    git checkout ac00290 && \
    mkdir build && cd build && \
    cmake .. && \
    make dcmqrscp $MAKE_OPT

# Setup Server
COPY --chown=ubuntu:ubuntu dcmqrscp.cfg ${WORKDIR}/dcmqrscp.cfg
COPY --chown=ubuntu:ubuntu dicom.dic ${WORKDIR}/dcmtk/dcmdata/data/dicom.dic

ENV DCMDICTPATH=${WORKDIR}/dcmtk/dcmdata/data/dicom.dic

RUN cd /usr/local/etc/ && \
    mkdir dcmtk-3.6.9 && \
    cp $WORKDIR/dcmqrscp.cfg dcmtk-3.6.9/