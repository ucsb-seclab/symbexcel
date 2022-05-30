#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import z3
import subprocess
import traceback
from typing import Callable

import IPython
import dill as pickle
from os.path import join as joinpath
from networkx.drawing.nx_agraph import write_dot

from symbexcel import SimulationManager, State
from symbexcel.cfg import generate_graph

# LOGGING_FORMAT = '%(levelname)s | %(name)s | %(message)s'
LOGGING_FORMAT = '%(message)s'
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger('symbexcel')


def restore(f):
    try:
        log.info(f'[Restoring checkpoint {args.restore}]')
        with open(args.restore, 'rb') as f:
            return pickle.load(f)
    except:
        traceback.print_exc()
        log.error(f'[Unable to restore checkpoint {args.restore}]')
        exit(1)

def main(args):
    if not os.path.exists(args.file):
        log.error('Input file does not exist')
        return

    if args.skip and args.iocs and os.path.exists(args.iocs):
        log.info(f'Skipping already processed file {args.file}')
        return

    log.info(f'Processing file {args.file}')

    if args.restore:
        simgr = restore(args.restore)
    else:
        keep_predecessors = args.history or 0
        simgr = None
        try:
            simgr = SimulationManager(filename=args.file, com=args.com, nocache=args.nocache,
                                      keep_predecessors=keep_predecessors, enable_delegations=args.delegations,
                                      default_handlers=args.default_handlers)  # check_symbolic_args=args.check_symbolic_args)
            log.info(f'Real path is {simgr.excel_doc.path}')
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            
            if simgr:
                simgr.set_error(f'{exc_type.__name__} at {fname}:{exc_tb.tb_lineno}')
            else:
                log.error(f'[ERROR] {exc_type.__name__} at {fname}:{exc_tb.tb_lineno}')
            log.exception(f'LoadingError: Failed to load file {args.file}')
            exit(1)
    
    find: Callable[[State], bool] = lambda s: str(s.simgr.insns_count) in args.breakpoints

    try:
        log.info(f'[Starting deobfuscation]')
        while len(simgr.active) > 0:
            simgr.run(find=find, checkpoint=args.checkpoint, timeout=args.timeout)

            print('-' * 30 + '\n' + str(simgr))
            if len(simgr.found) > 0:
                IPython.embed()

            simgr.move(from_stash='found', to_stash='active')

        if args.iocs:
            log.info(f'[Exporting iocs]')
            try:
                with open(args.iocs, 'w') as f:
                    for idx, state in enumerate(simgr.states):
                        if state.iocs:
                            f.write('\n\nIOCs for State %d' % idx)
                            for ioc in state.iocs:
                                f.write(f'\n\t{ioc}')
            except:
                log.error(f'Failed to export iocs')

        if args.models:
            log.info(f'[Exporting models]')
            try:
                with open(args.models, 'w') as f:
                    for idx, state in enumerate(simgr.states):
                        if state.solver._solver.check() == z3.sat:
                            model = simgr.states[idx].solver._solver.model()
                            f.write('\n\nModel for State %d' % idx)
                            for v in model:
                                f.write(f'\n\t{v} = {model[v]}')
            except:
                log.error(f'Failed to export models')


        if args.cfg:
            log.info(f'[Generating graph]')
            try:
                cfg = generate_graph(simgr, formula=False)

                # dump graph as .dot and .png
                write_dot(cfg, f'{args.cfg}.dot')
                # subprocess.check_call(['dot', '-Tpng', f'{args.cfg}.dot', '-o', args.cfg])
            except:
                log.error(f'Failed to generate graph')

        if args.simgr:
            log.info(f'[Exporting simgr]')
            try:
                # Save the result
                with open(args.simgr, 'wb') as f:
                    tmp = simgr.excel_doc
                    simgr.excel_doc = None
                    pickle.dump(simgr, f)
                    simgr.excel_doc = tmp
            except:
                log.error(f'Failed to export simgr')

        if args.interactive:
            IPython.embed()

        if simgr.error:
            log.error(f'Finished processing file {simgr.excel_doc.path}, but the Simulation Manager has errors')
            exit(2)
        else:
            log.info(f'Finished processing file {simgr.excel_doc.path}')

    except KeyboardInterrupt:
        exit(3)
    except Exception as e:
        log.exception(f'Failed to process file {simgr.excel_doc.path}')
        exit(4)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser._action_groups.pop()
    required = parser.add_argument_group('Required arguments')
    optional = parser.add_argument_group('Optional arguments')
    comopts  = parser.add_argument_group('COM specific arguments')

    required.add_argument('-f', '--file', type=str, action='store',
                          help='Path of the malicious sample', required=True)

    optional.add_argument('-d', '--debug', action='store_true',
                            help='Enable debug output')
    optional.add_argument('--breakpoints', type=str, nargs='+', default=[], action='store',
                            help='Set a breakpoint at a specific instruction count')
    optional.add_argument('--skip', action='store_true',
                            help='Skip if already processed')
    optional.add_argument('--checkpoint', type=int, action='store',
                            help='Create a checkpoint at a specific instruction count')
    optional.add_argument('--history', type=int, action='store',
                          help='Number of states to keep in history')
    optional.add_argument('--restore', type=str, action='store',
                            help='Restore a checkpoint')
    optional.add_argument('-i', '--interactive', action='store_true',
                            help='Drop an IPython shell after the execution')
    optional.add_argument('-t', '--timeout', type=int, action='store', default=0,
                            help='Timeout value')

    optional.add_argument('--default-handlers', action='store_true',
                            help='Use default handlers (don\'t abort execution)')
    # optional.add_argument('--check-symbolic-args', action='store_true',
    #                         help='Check for symbolic arguments')

    optional.add_argument('--log', type=str, action='store',
                            help='Path to save the logfile')
    optional.add_argument('--simgr', type=str, action='store',
                            help='Path to save the simgr')
    optional.add_argument('--cfg', type=str, action='store',
                            help='Path to save the CFG')
    optional.add_argument('--iocs', type=str, action='store',
                            help='Path to save the Indicators of Compromise (IOCs)')
    optional.add_argument('--models', type=str, action='store',
                            help='Path to save the final models')

    comopts.add_argument('--com', action='store_true',
                         help='Use COM server to process a sample')
    comopts.add_argument('--delegations', action='store_true',
                         help='Use COM server with delegations')
    comopts.add_argument('--nocache', default=False, action="store_true",
                         help='Force the COM server to process the sample')

    args = parser.parse_args()

    # setup logging
    log.setLevel('INFO')

    if args.debug:
        logging.getLogger('symbexcel').setLevel('DEBUG')
    else:
        logging.getLogger('symbexcel').setLevel('CRITICAL')

    if args.log:
        fh = logging.FileHandler(args.log)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logging.getLogger('symbexcel').addHandler(fh)
        logging.getLogger('symbexcel').setLevel(logging.DEBUG)
        logging.getLogger('symbexcel').propagate = False

    main(args)
