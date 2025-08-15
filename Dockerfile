FROM ubuntu:24.04
# docker build -t ubuntu-ego .
RUN apt-get update && apt-get install -y gcc wget gnupg curl
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN curl -s https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN apt update
RUN apt-get install -y libsgx-dcap-ql libsgx-enclave-common
RUN wget https://github.com/edgelesssys/edgelessrt/releases/download/v0.4.10/edgelessrt_0.4.10_amd64_ubuntu-24.04.deb
RUN wget https://github.com/edgelesssys/ego/releases/download/v1.7.2/ego_1.7.2_amd64_ubuntu-24.04.deb
RUN dpkg -i *.deb
RUN rm -f *.deb
