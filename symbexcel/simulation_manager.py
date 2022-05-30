import logging
import os
import re
import signal
import sys
from typing import Callable, List, TYPE_CHECKING, Union

import dill as pickle
from oletools.olevba import VBA_Parser
from oletools.thirdparty.oledump.plugin_biff import cBIFF

from symbexcel.excel_wrapper import ExcelWrapper, parse_excel_doc
from .boundsheet import Cell
from .state import State

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# define useful type shortcuts
Stash = List[State]


class SimulationManager:

    def __init__(self, excel_doc=None, filename=None, com=None, nocache=None, keep_predecessors=0,
                 enable_delegations=False, default_handlers=False, check_symbolic_args=True):
        """
        :param excel_doc: The excel document that you want to analyse
        """
        if not excel_doc and ExcelWrapper.get_file_type(filename) is None:
            raise RuntimeError('The sample has an invalid filetype, aborting')

        self.excel_doc = excel_doc or parse_excel_doc(filename, com, nocache)
        self.MAX_INSNS = 1000000

        self.sha1 = self.excel_doc.sha1

        self.vba_code = ''
        self.dconn = dict()
        self.dconn_cells = list()

        self.enable_delegations = enable_delegations
        self.default_handlers = default_handlers
        self.check_symbolic_args = check_symbolic_args

        self.keep_predecessors = keep_predecessors
        self.insns_count = 0
        self.symbolic = False
        self._halt    = False
        self.error    = list()
        # create an XLM parser
        self.xlm_parser = ExcelWrapper.get_parser()

        # initialize empty stashes
        self._stashes = {
            'active': [],
            'deadended': [],
            'found': [],
            'pruned': []
        }

        sheets      = self.excel_doc.get_sheets()
        entrypoints = self.excel_doc.get_entrypoints()

        defined_names = self.excel_doc.get_defined_names()
        log.debug(f'Defined names: {defined_names}')

        _vba_run_cell_regex_str = r'Application\.Run Sheets\(\"(?P<sheet>.*?)\"\)\.Range\(\"(?P<cell>.*?)\"\)'
        _vba_run_cell_regex = re.compile(_vba_run_cell_regex_str)
        _vba_run_name_regex_str = r'Application\.Run \(\"(?P<name>.*?)\"\)'
        _vba_run_name_regex = re.compile(_vba_run_name_regex_str)
        try:
            vbaparser = VBA_Parser(filename)

            # try to parse entrypoints from VBA code
            vba_code = vbaparser.get_vba_code_all_modules()

            for i, (sheet, cell_str) in enumerate(_vba_run_cell_regex.findall(vba_code)):
                entrypoints += [(f'vba_run_cell_{i}', sheets[sheet][cell_str])]
            for i, name in enumerate(_vba_run_name_regex.findall(vba_code)):
                entrypoints += [(f'vba_run_name_{i}', defined_names[name.lower()])]

            # parse DCONN
            for excel_stream in ('Workbook', 'Book'):
                if vbaparser.ole_file.exists(excel_stream):
                    data = vbaparser.ole_file.openstream(excel_stream).read()
                    biff_plugin = cBIFF(name=[excel_stream], stream=data, options='-o DCONN -s')
                    conn = biff_plugin.Analyze()
                    if conn:
                        self.dconn[conn[-1].strip().lower()] = conn[-2]
        except:
            self.set_error('OleVBA parsing failed')

        if len(entrypoints) == 0:
            self.set_error('Entrypoint(s) not found!')
            return

        if self.dconn:
            print(f'DCONN entries: {self.dconn}')

        # Create initial states.
        for name, cell in entrypoints:
            if not isinstance(cell, Cell):
                log.warning('Skipping invalid entry point: %s %s' % (name, cell))
                continue

            log.info(f'Entry point {name}: "{cell.a1}"')
            state = State(simgr=self, curr_cell=cell, memory=sheets)
            self.active.append(state)

    def set_error(self, s):
        log.error(f'[ERROR] {s}')
        self.error += [s]

    def __getstate__(self):
        state = dict(self.__dict__)
        # del state['excel_doc']
        del state['xlm_parser']
        return state

    def __setstate__(self, state):
        self.__dict__ = state
        self.xlm_parser = ExcelWrapper.get_parser()

    @property
    def states(self) -> Union[State, None]:
        """
        :return: All the states
        """
        return sum(self._stashes.values(), [])

    @property
    def active(self) -> Stash:
        """
        :return: Active stash
        """
        return self._stashes['active']

    @property
    def deadended(self) -> Stash:
        """
        :return: Deadended stash
        """
        return self._stashes['deadended']

    @property
    def found(self) -> Stash:
        """
        :return: Found stash
        """
        return self._stashes['found']

    @property
    def one_active(self) -> Union[State, None]:
        """
        :return: First element of the active stash, or None if the stash is empty
        """
        if len(self._stashes['active']) > 0:
            return self._stashes['active'][0]
        else:
            return None

    @property
    def one_deadended(self) -> Union[State, None]:
        """
        :return: First element of the deadended stash, or None if the stash is empty
        """
        if len(self._stashes['deadended']) > 0:
            return self._stashes['deadended'][0]
        else:
            return None

    @property
    def one_found(self) -> Union[State, None]:
        """
        :return: First element of the found stash, or None if the stash is empty
        """
        if len(self._stashes['found']) > 0:
            return self._stashes['found'][0]
        else:
            return None

    def halt(self, signum, frame):
        log.error(f'[TIMEOUT] Simulation manager for {self.sha1} timed out')

        for state in self.states:
            state.halt = True
            state.error = 'TimeoutError'

        self.set_error("TIMEOUT")
        self._halt = True

    def move(self, from_stash: str, to_stash: str, filter_func: Callable[[State], bool] = lambda s: True) -> None:
        """
        Move all the states that meet the filter_func condition from from_stash to to_stash
        :param from_stash: Source stash
        :param to_stash: Destination Stash
        :param filter_func: A function that discriminates what states should be moved
        :return: None
        """
        for s in list(self._stashes[from_stash]):
            if filter_func(s):
                self._stashes[from_stash].remove(s)
                self._stashes[to_stash].append(s)

    def step(self, n: int = 1) -> None:
        """
        Perform n steps (default is 1), after each step move all the halted states to the deadended stash
        :param n: Number of steps
        :return: None
        """
        for _ in range(n):
            for state in list(self.active):
                try:
                    state.step()
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    
                    log.exception('Something went wrong during the deobfuscation.')
                    self.set_error(f'{exc_type.__name__} at {fname}:{exc_tb.tb_lineno}')
                    state.error = e.__class__

            self.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.halt or s.error)

    def run(self, find: Callable[[State], bool] = lambda s: False, checkpoint=None, timeout=0) -> None:
        """
        Run the simulation manager, until the `find` condition is met. The analysis will stop when there are no more
        active states or some states met the `find` condition (these will be moved to the found stash)
        example: simgr.run(find=lambda s: '=ALERT' in s.formula)
        :param find: Function that will be called after each step. The matching states will be moved to the found stash
        :param timeout: Max running time, in seconds
        :return: None
        """

        # handle timeout
        signal.signal(signal.SIGALRM, self.halt)
        signal.alarm(timeout)

        try:
            while len(self.active) > 0 and len(self.found) == 0 and not self._halt:
                if checkpoint and self.insns_count == checkpoint:
                    with open(f'/tmp/symbexcel.{self.sha1}.checkpoint.{checkpoint}', 'wb') as f:
                        pickle.dump(self, f)
                self.move(from_stash='active', to_stash='found', filter_func=find)

                self.step()

                self.insns_count += 1
                if self.insns_count >= self.MAX_INSNS:
                    log.error(f"Exceeded MAX_INSNS ({self.MAX_INSNS})")
                    self.set_error(f"Exceeded MAX_INSNS ({self.MAX_INSNS})")
                    self.move(from_stash='active', to_stash='pruned')
                    self._halt = True
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            
            log.exception(f'Exception while stepping the Simulation Manager')
            self.set_error(f'{exc_type.__name__} at {fname}:{exc_tb.tb_lineno}')
        finally:
            signal.alarm(0)
            if checkpoint == -1:
                with open(f'/tmp/symbexcel.{self.sha1}.checkpoint.{checkpoint}', 'wb') as f:
                    pickle.dump(self, f)

    def __str__(self) -> str:
        stashes_str = [f'{len(stash)} {stash_name}' #  {[s for s in stash]}'
                       for stash_name, stash in self._stashes.items() if len(stash)]
        errored_count = len([s for stash_name, stash in self._stashes.items() if len(stash) for s in stash if s.error])
        stashes_str += [f'({errored_count} errored)']
        return f'<SimulationManager[{self.insns_count}] with {", ".join(stashes_str)}>'

    def __repr__(self) -> str:
        return self.__str__()
