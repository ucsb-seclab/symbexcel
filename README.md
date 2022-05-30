# symbexcel

[![Tests](https://github.com/ucsb-seclab/symbexcel/actions/workflows/python-app.yml/badge.svg)](https://github.com/ucsb-seclab/symbexcel/actions/workflows/python-app.yml)


symbexcel is a symbolic deobfuscator for XL4 macros, currently developed by [Nicola Ruaro](https://twitter.com/_ruaronicola) and [Fabio Pagani](https://twitter.com/pagabuc).

Among a number of other things, symbexcel:

- Supports malware analysts to reverse complex XL4 malware
- Automatically extracts Indicators of Compromise (IOCs) to improve detection of malicious Excel documents

This tool draws some concepts from [angr](https://github.com/angr/angr/), and is based on the excellent [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) by [DissectMalware](https://twitter.com/dissectmalware). Big kudos to him!

## Quick Start

1. Download symbexcel:
```bash
    git clone https://github.com/ucsb-seclab/symbexcel && cd symbexcel
```

2. Create a virtual environment (recommended but not required)
```bash
    mkvirtualenv symbexcel
    workon symbexcel
```

3. Install symbexcel and its dependencies:
```bash
    pip install -e .
```

4. Start the analysis of a malicious XL4 sample:
```bash
    python run.py --file /path/to/malicious/excel.xls --iocs
```

## Usage


```bash
$ python run.py -h
    usage: run.py [-h] -f FILE [-d] [--iocs] [--breakpoints BREAKPOINTS [BREAKPOINTS ...]] [--checkpoint CHECKPOINT] [--restore RESTORE] [-i] [--cfg] [-t TIMEOUT] [--com] [--nocache]

    Required arguments:
      -f FILE, --file FILE  Path of the malicious sample

    Optional arguments:
      -d, --debug           Enable debug output
      --iocs                Print Indicators of Compromise (IOCs)
      --breakpoints BREAKPOINTS [BREAKPOINTS ...]
                            Set a breakpoint at a specific instruction count
      --checkpoint CHECKPOINT
                            Create a checkpoint at a specific instruction count
      --restore RESTORE     Restore a checkpoint
      -i, --interactive     Drop an IPython shell after the execution
      --cfg                 Save the CFG to /tmp/<sample name>.dot
      -t TIMEOUT, --timeout TIMEOUT
                            Timeout value

    COM specific arguments:
      --com                 Use COM server to process a sample
      --nocache             Force the COM server to process the sample
```

## symbexcel COM Server

symbexcel can either use [xlrd2](https://github.com/DissectMalware/xlrd2/) or Office [VBA](https://docs.microsoft.com/en-us/office/vba/api/overview/excel) to parse and extract the content of Excel 4 macrosheets.
The VBA API are exposed through a COM server, and interactions from Python code are possible using the [pywin32](https://pypi.org/project/pywin32/) package.

You can find all the information on how to setup the symbexcel COM server in the [symbexcel-server](https://github.com/ucsb-seclab/symbexcel-server) repository.
Once the server is up and running:

1. Add the server IP address in the HOST variable of symbexcel/excel_wrapper/com_config.env.

2. Add the option `--com` to the command line of symbexcel.

## symbexcel as a Library

You can use also use this project as a Python library (`import symbexcel`) in your own projects.
You can find some good examples for this in the `tests` folder.
Using this project as a library will allow your code to single-step (or n-step) the simulation manager, use the `find` argument in `SimulationManager.run()` to specify a search function, etc.


```python
from symbexcel import SimulationManager
from symbexcel.excel_wrapper import parse_excel_doc

excel_doc = parse_excel_doc('tests/bins/test_symbolic.xls')

simgr = SimulationManager(excel_doc)

simgr.step(n=1)
simgr.run(find=lambda s: '=ALERT' in s.formula)

print(simgr.one_found.formula)
```

## Docker
You can use the `Dockerfile` and `docker-compose.yml` from this repo to create a docker container and run the `create_clusters` script on a set of malware samples.
The folder specified in the `input` and `output` environment variables will be mounted as `/input` and `/output` in the container. You can pass any arguments for the `create_clusters` script in the `args` environment variable.

```bash
input=/data/xl4_dataset/ output=/data/symbexcel/docker_clustering args="--input /input --output /output --jobs 96 --timeout 1200 --debug --logfile" docker-compose up &> /data/symbexcel/docker_clustering_log &
```

## Tests

After installing symbexcel, you can run all tests with `cd tests && pytest`.
Alternatively, you can manually execute any test, i.e. `cd tests && python test_file_formats.py`.
Creating new tests should be straightforward by looking at the existing test routines.

## Samples

There's a repository from Lastline at https://github.com/Lastline-Inc/xl4samples with some public malicious samples.
Download and run them at your own risk!