# Use an official Python runtime as a parent image
FROM ubuntu:16.04

# Add user
RUN useradd -m maloss && adduser maloss sudo
RUN mkdir -p /etc/sudoers.d && echo "maloss ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/maloss


# Install toolchain 
RUN apt-get update -yqq
RUN apt-get install -yqq sudo curl wget php git ruby-full rubygems-integration nuget python python-pip npm jq vim strace nano
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yqq tzdata


# Copy contents to inside contianer
ARG MALOSS_HOME=/home/maloss
ADD config ${MALOSS_HOME}/config
ADD data ${MALOSS_HOME}/data
ADD src ${MALOSS_HOME}/src
ADD main ${MALOSS_HOME}/main

# Install dependencies
WORKDIR ${MALOSS_HOME}
#RUN ${MALOSS_HOME}/src/install_dep.sh
#RUN ${MALOSS_HOME}/src/install_protoc.sh
#RUN ${MALOSS_HOME}/src/install_nuget.sh
#RUN ${MALOSS_HOME}/main/install_dep.sh

# Change current user and create folders
RUN chown -R maloss:maloss ${MALOSS_HOME}
USER maloss 

