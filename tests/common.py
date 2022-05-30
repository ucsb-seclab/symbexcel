import argparse
import logging
import os
from typing import Dict, Tuple, Union

from symbexcel.excel_wrapper import XLSWrapper
from symbexcel.excel_wrapper import parse_excel_doc


LOGGING_FORMAT = '%(levelname)s | %(name)s | %(message)s'
logging.basicConfig(level=logging.ERROR, format=LOGGING_FORMAT)

EMPTY_XLS_FILE = os.path.join(os.path.dirname(__file__), 'bins/empty.xls')

INTERACTIVE = False
BREAKPOINTS = []

def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-d', '--debug', action='store_true',
                            help='Enable Debug output')
    arg_parser.add_argument('-b', '--breakpoints', type=str, nargs='+', default=[], action='store',
                            help='Set a breakpoint at cell. Example -b A1 A2')
    arg_parser.add_argument('-i', '--interactive', action='store_true',
                            help='Drop an IPython shell after the execution')
    args = arg_parser.parse_args()
    if args.debug:
        logging.getLogger('symbexcel').setLevel(logging.DEBUG)

    if args.interactive or args.breakpoints:
        global INTERACTIVE
        INTERACTIVE = True

    global BREAKPOINTS
    BREAKPOINTS = args.breakpoints


def get_excel_doc(memory: Dict[str, Tuple[Union[str, None], Union[str, None]]] = None) -> XLSWrapper:
    """
    Creates a custom excel document, starting from the empty template in bins/empty.xls

    # example:
    # note that the default value should be None, not '' (empty string)
    memory = {
        'A1': (None, 'formula'),
        'A2': ('value', None),
    }

    get_excel_doc(memory=memory)

    :param memory: dictionary mapping cells to (value, formula)
    :return: Excel document
    """

    excel_doc = XLSWrapper(EMPTY_XLS_FILE)

    memory = memory or dict()

    # macro sheet is Macro1, auto_open is A1 (empty.xls is a known empty document that we created)
    macrosheet = excel_doc.get_macrosheets()['Macro1']

    # set the value and formula for all cells
    for cell, (value, formula) in memory.items():
        # column, row = re.match(r"([A-Z]+)([0-9]+)", 'A1', re.I).groups()

        macrosheet[cell].value = value
        macrosheet[cell].formula = formula

    return excel_doc


def get_excel_bin(filename) -> str:
    path = os.path.join(os.path.dirname(__file__), "bins", filename)
    return parse_excel_doc(path)
