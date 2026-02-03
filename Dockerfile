FROM ubuntu:24.04
# docker build -t ubuntu-ego .
RUN apt-get update && apt-get install -y gcc wget gnupg curl
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN curl -s https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN apt update
RUN apt-get install -y libsgx-dcap-ql libsgx-enclave-common
RUN wget https://github.com/edgelesssys/edgelessrt/releases/download/v0.5.1/edgelessrt_0.5.1_amd64_ubuntu-24.04.deb
RUN wget https://github.com/edgelesssys/ego/releases/download/v1.8.1/ego_1.8.1_amd64_ubuntu-24.04.deb
RUN dpkg -i *.deb
RUN rm -f *.deb
