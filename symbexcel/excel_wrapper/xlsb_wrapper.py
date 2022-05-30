import logging

from pyxlsb2 import open_workbook
from pyxlsb2.formula import Formula

from symbexcel.boundsheet import Boundsheet, Cell
from .excel_wrapper import ExcelWrapper

log = logging.getLogger(__name__)

class XLSBWrapper(ExcelWrapper):
    def __init__(self, xlsb_doc_path):
        self.xls_workbook = open_workbook(xlsb_doc_path)
        super().__init__(xlsb_doc_path)

    def load_names(self):
        for key, val in self.xls_workbook.defined_names.items():
            name = key.lower()
            value = val.formula

            # try to parse a cell address
            sheet, col, row = Cell.parse_cell_addr(value)

            if sheet is None or col is None or row is None:
                self._defined_names[name] = value
            else:
                cell = self.get_cell(sheet, col, row)
                if cell:
                    self._defined_names[name] = cell
                else:
                    log.warning(f"Can't parse oREF defined name {value}")

    def load_cells(self, boundsheet):
        with self.xls_workbook.get_sheet_by_name(boundsheet.name) as sheet:
            for row in sheet:
                for cell in row:
                    tmp_cell = Cell()
                    tmp_cell.row = cell.row_num + 1
                    tmp_cell.column = Cell.convert_to_column_name(cell.col + 1)

                    tmp_cell.value = cell.value
                    tmp_cell.sheet = boundsheet
                    formula_str = Formula.parse(cell.formula)
                    if formula_str._tokens:
                        try:
                            tmp_cell.formula = '=' + formula_str.stringify(self.xls_workbook)
                        except NotImplementedError as exp:
                            print('ERROR({}) {}'.format(exp, str(cell)))
                        except Exception:
                            print('ERROR ' + str(cell))
                    if tmp_cell.value is not None or tmp_cell.formula is not None:
                        boundsheet[tmp_cell.get_local_address_pair()] = tmp_cell

    def load_macrosheets(self):
       for xlsb_sheet in self.xls_workbook.sheets:
           if xlsb_sheet.type == 'macrosheet':
               with self.xls_workbook.get_sheet_by_name(xlsb_sheet.name) as sheet:
                   macrosheet = Boundsheet(xlsb_sheet.name, 'macrosheet')
                   self.load_cells(macrosheet)
                   self._macrosheets[macrosheet.name] = macrosheet

                # self.load_macro_cells(macrosheet, workbook)
                # self._macrosheets[workbook.name] = macrosheet

    def load_worksheets(self):
       for xlsb_sheet in self.xls_workbook.sheets:
           if xlsb_sheet.type == 'worksheet':
               with self.xls_workbook.get_sheet_by_name(xlsb_sheet.name) as sheet:
                   worksheet = Boundsheet(xlsb_sheet.name, 'worksheet')
                   self.load_cells(worksheet)
                   self._worksheets[worksheet.name] = worksheet

    def get_cell_info(self, sheet_name, col, row, info_type_id):
        data = None
        not_exist = False
        not_implemented = True

        return data, not_exist, not_implemented
