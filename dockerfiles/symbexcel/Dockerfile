FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt-get update --fix-missing && apt-get install -y git graphviz graphviz-dev python3-dev python3-pip parallel
RUN python3 -m pip install setuptools

# install symbexcel
ADD . /symbexcel
ADD dockerfiles/symbexcel/run.sh /symbexcel/
WORKDIR /symbexcel
RUN pip install -e /symbexcel

# run analysis
ENTRYPOINT ["bash", "/symbexcel/run.sh"]
