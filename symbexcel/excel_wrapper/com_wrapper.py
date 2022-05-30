import logging
import pickle
import sys
import xmlrpc.client

import dotenv

from symbexcel.boundsheet import Boundsheet, Cell
from symbexcel.excel_wrapper import ExcelWrapper

log = logging.getLogger(__name__)

config = dotenv.dotenv_values(dotenv.find_dotenv('com_config.env'))

class COMWrapper(ExcelWrapper):

    def __init__(self, path, nocache=False):
        self.xls_workbook = None
        self.rpath        = None
        self.client       = None
        self.nocache = nocache
        self.connect_client()

        with open(path, 'rb') as f:
            self.blob = f.read()

        try:
            self.rpath = self.client.start_excel(self.blob)
        except xmlrpc.client.Fault as e:
            raise ValueError(e.faultString) from None

        r = self.client.process(self.rpath, self.nocache)
        self.result = pickle.loads(r.data)
        self.rpath  = self.result['rpath']

        super().__init__(path)
        self.load_comments()
        self.load_vba()
        # self.client.stop_excel(self.rpath)

    def __getstate__(self):
        self.client = None

    def connect_client(self):
        if self.client:
            return

        if not config['COM_USER']:
            print('[-] Invalid COM configuration in symbexcel/excel_wrapper/com_config.env, aborting.')
            sys.exit(0)

        self.client = xmlrpc.client.ServerProxy('http://%s:%s@%s/supersecretendpointV3' % (config['COM_USER'],
                                                                                           config['COM_PASS'],
                                                                                           config['COM_HOST']),
                                                allow_none=True)

    def load_worksheets(self):
        for name in self.result['worksheets']:
            worksheet = Boundsheet(name, 'Worksheet')
            self.load_cells(worksheet, self.result['worksheets'][name])
            self._worksheets[name] = worksheet

    def load_macrosheets(self):
        for name in self.result['macrosheets']:
            macrosheet = Boundsheet(name, 'Macrosheet')
            self.load_cells(macrosheet, self.result['macrosheets'][name])
            self._macrosheets[name] = macrosheet

    def load_names(self):
        names = {k.lower(): v for k, v in self.result['names'].items()}

        for name, (value, count) in names.items():
            if count == False:
                result = value
            elif count == 1:
                addr   = Cell.parse_cell_addr(value.lstrip('='))
                result = self.get_cell(*addr)
            elif count > 1:
                addr   = Cell.parse_range_addr(value.lstrip('='))
                try:
                    result = self.get_range(*addr)
                except:
                    continue
            self._defined_names[name] = result

        # Here we resolve names that reference other names.
        for name, result in self._defined_names.items():
            while result is None:
                value, _ = names[name]
                result = self._defined_names[value.lstrip("=").lower()]
            self._defined_names[name] = result

    def load_comments(self):
        for s in self.result['comments']:
            for addr, comment in self.result['comments'][s].items():
                a1 = s + '!' + addr
                self._comments[a1] = comment

    def load_vba(self):
        if self.result['vba'] is not None:
            self._vba = self.result['vba']
        else:
            pass
            # raise NotImplementedError('VBA Project is protected, aborting.')

    def load_cells(self, sheet, cells):
        for address, (value, formula) in cells.items():
            sheet[address].value   = value
            sheet[address].formula = formula

    def execute_formula(self, sheet_name, col, row, formula, accessed):
        self.connect_client()

        # prepare accessed names to sync
        for name in accessed['names']:
            if isinstance(accessed['names'][name], Cell):
                accessed['names'][name] = f"={accessed['names'][name].r1c1}"
        # prepare accessed cells to sync
        for cell in accessed['cells']:
            if isinstance(accessed['cells'][cell], Cell):
                accessed['cells'][cell] = f"={accessed['cells'][cell].r1c1}"

        result, accessed = self.client.execute_formula(self.rpath, sheet_name, col, row, formula, accessed)
        return result, accessed

    def get_cell_info(self, sheet_name, col, row, info_type_id):
        self.connect_client()

        return self.client.get_cell_info(self.rpath, sheet_name, col, row, info_type_id, self.nocache)

    def get_workbook_info(self, info_type_id):
        self.connect_client()

        return self.client.get_workbook_info(self.rpath, info_type_id, self.nocache)

    # def __del__(self):
    #     if not self.rpath:
    #         return

    #     self.connect_client()

        # return self.client.close_excel(self.rpath)
