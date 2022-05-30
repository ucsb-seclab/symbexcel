FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt-get update --fix-missing && apt-get install -y python3-dev python3-pip git parallel
RUN python3 -m pip install setuptools

# install symbexcel
# ADD ./run.sh /xlm_macro_deobfuscator/run.sh
RUN pip install -U https://github.com/DissectMalware/xlrd2/archive/master.zip
RUN pip install -U https://github.com/DissectMalware/pyxlsb2/archive/master.zip
RUN pip install -U https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/v0.2.0.zip

# run analysis
ENTRYPOINT ["bash", "/xlm_macro_deobfuscator/run.sh"]
