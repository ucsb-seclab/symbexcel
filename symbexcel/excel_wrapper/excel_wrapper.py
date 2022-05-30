import os
import hashlib
import xlrd2

from enum import Enum
from lark import Lark
from symbexcel.boundsheet import Cell, Range


class XlApplicationInternational(Enum):
    # https://docs.microsoft.com/en-us/office/vba/api/excel.xlapplicationinternational
    xlLeftBracket = 10
    xlListSeparator = 5
    xlRightBracket = 11


class RowAttribute(Enum):
    Height = 0
    Spans = 1


class ExcelWrapper:
    xl_international_flags = {XlApplicationInternational.xlLeftBracket: '[',
                              XlApplicationInternational.xlListSeparator: ',',
                              XlApplicationInternational.xlRightBracket: ']'}

    def __init__(self, path):
        self.path = path

        with open(path, 'rb') as f:
            self.sha1 = hashlib.sha1(f.read()).hexdigest()

        self._macrosheets   = {}
        self._worksheets    = {}
        self._defined_names = {}
        self._comments      = {}
        self._vba           = {}

        self.load_sheets()
        self.load_names()

    @staticmethod
    def get_file_type(path):
        file_type = None
        with open(path, 'rb') as input_file:
            start_marker = input_file.read(2)
            if start_marker == b'\xD0\xCF':
                file_type = 'xls'
            elif start_marker == b'\x50\x4B':
                file_type = 'xlsm/b'
        if file_type == 'xlsm/b':
            raw_bytes = open(path, 'rb').read()
            if bytes('workbook.bin', 'ascii') in raw_bytes:
                file_type = 'xlsb'
            else:
                file_type = 'xlsm'
        return file_type

    @staticmethod
    def get_parser():
        grammar_file_path = os.path.join(os.path.dirname(__file__), 'xlm-macro.lark.template')
        with open(grammar_file_path, 'r', encoding='utf_8') as grammar_file:
            macro_grammar = grammar_file.read()
            macro_grammar = macro_grammar.replace('{{XLLEFTBRACKET}}',
                                                  ExcelWrapper.xl_international_flags.get(
                                                      XlApplicationInternational.xlLeftBracket))
            macro_grammar = macro_grammar.replace('{{XLRIGHTBRACKET}}',
                                                  ExcelWrapper.xl_international_flags.get(
                                                      XlApplicationInternational.xlRightBracket))
            macro_grammar = macro_grammar.replace('{{XLLISTSEPARATOR}}',
                                                  ExcelWrapper.xl_international_flags.get(
                                                      XlApplicationInternational.xlListSeparator))
            xlm_parser = Lark(macro_grammar, parser='lalr')

        return xlm_parser

    def reevaluate_name_formulas(self):
        book = self.xls_workbook
        for idx, nobj in enumerate(book.name_obj_list):
            name = nobj.name.lower()
            if name == 'auto_open' or name == 'auto_close':
                xlrd2.formula.evaluate_name_formula(book, nobj, idx)
                sheet, col, row = Cell.parse_cell_addr(nobj.result.text)
                cell = self.get_cell(sheet, col, row)
                if cell:
                    yield name, cell

    def get_entrypoints(self):
        entrypoints  = []
        entrypoints += self.get_defined_name('auto_open', full_match=False)
        entrypoints += self.get_defined_name('auto_close', full_match=False)
        entrypoints += self.get_defined_name('auto_activate', full_match=False)
        entrypoints += self.get_defined_name('auto_deactivate', full_match=False)
        if len(entrypoints) == 0 and self.xls_workbook:
            entrypoints = list(self.reevaluate_name_formulas())

        for idx, (label, cell) in enumerate(entrypoints):
            if isinstance(cell, Range):
                entrypoints[idx] = (label, cell.get_first_cell())
        return entrypoints

    def get_defined_name(self, name, full_match=True):
        result = []
        name = name.lower().replace('[', '')

        if full_match:
            if name in self.get_defined_names():
                result = self._defined_names[name]
        else:
            for defined_name, cell_address in self.get_defined_names().items():
                if defined_name.startswith(name):
                    result.append((defined_name, cell_address))

        # By @JohnLaTwC:
        # if no matches, try matching 'name' by looking for its characters
        # in the same order (ignoring junk chars from UTF16 etc in between. Eg:
        # Auto_open:
        #   match:    'a_u_t_o___o__p____e_n'
        #   not match:'o_p_e_n_a_u_to__'
        # Reference: https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/
        # Sample: e23f9f55e10f3f31a2e76a12b174b6741a2fa1f51cf23dbd69cf169d92c56ed5
        if isinstance(result, list) and len(result) == 0:
            for defined_name, cell_address in self.get_defined_names().items():
                lastidx = 0
                fMatch = True
                for c in name:
                    idx = defined_name.find(c, lastidx)
                    if idx == -1:
                        fMatch = False
                    lastidx = idx
                if fMatch:
                    result.append((defined_name, cell_address))
                ##print("fMatch for %s in %s is %d:" % (name,defined_name, fMatch))

        return result

    def get_cell(self, sheet, col, row):
        if self._worksheets and sheet in self._worksheets:
            return self._worksheets[sheet][(col, row)]
        if self._macrosheets and sheet in self._macrosheets:
            return self._macrosheets[sheet][(col, row)]

    def get_range(self, sheet, scol, srow, ecol, erow):
        if self._worksheets and sheet in self._worksheets:
            return self._worksheets[sheet][(scol, srow):(ecol, erow)]
        if self._macrosheets and sheet in self._macrosheets:
            return self._macrosheets[sheet][(scol, srow):(ecol, erow)]

    def get_sheets(self):
        sheets = dict(self.get_macrosheets())
        sheets.update(self.get_worksheets())
        return sheets

    def get_comments(self):
        return self._comments

    def get_vba(self):
        return self._vba

    def get_defined_names(self):
        return self._defined_names

    def get_macrosheets(self):
        return self._macrosheets

    def get_worksheets(self):
        return self._worksheets

    def load_sheets(self):
        self.load_macrosheets()
        self.load_worksheets()

    def load_macrosheets(self):
        raise NotImplementedError

    def load_worksheets(self):
        raise NotImplementedError

    def load_names(self):
        raise NotImplementedError

    def get_cell_info(self, sheet_name, col, row, info_type_id):
        raise NotImplementedError

    def get_workbook_info(self, idx):
        raise NotImplementedError
