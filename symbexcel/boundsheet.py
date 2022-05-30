import re
from collections.abc import MutableMapping
from itertools import product

MAX_ROWS = 1048576

class Boundsheet(MutableMapping):
    """
    Stores all cells, with lazy loading when an empty cell is requested
    """

    def __init__(self, name, sheet_type, *args, **kwargs):
        self.name = name
        self.type = sheet_type
        self.cells = dict()
        self.row_attributes = {}
        self.col_attributes = {}
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        if type(key) is str:
            _, column, row = Cell.parse_cell_addr(key)

        elif isinstance(key, slice):
            scol, srow = key.start
            ecol, erow = key.stop

            if srow != erow or scol != ecol:
                return Range(self, int(srow), int(erow), scol, ecol)
                #raise TypeError('Implement Proper Slicing')

            column, row = key.start

        else:
            column, row = key
            assert isinstance(column, str)
            assert isinstance(row, int)

        # lazy load an empty cell
        if (column, row) not in self.cells:
            cell = Cell()
            cell.sheet = self
            cell.column = column
            cell.row = row

            self.cells[(column, row)] = cell

        return self.cells[(column, row)]

    def __setitem__(self, key, value):
        if type(key) is str:
            _, column, row = Cell.parse_cell_addr(key)
        else:
            column, row = key

        self.cells[(column, row)] = value

    def __delitem__(self, key):
        if type(key) is str:
            _, column, row = Cell.parse_cell_addr(key)
        else:
            column, row = key

        del self.cells[(column, row)]

    def __iter__(self):
        return iter(self.cells)

    def __len__(self):
        return len(self.cells)

    def __deepcopy__(self):
        copy = Boundsheet(self.name, self.type)
        copy.cells = {k: v.__deepcopy__(copy) for k, v in self.cells.items()}
        return copy


class Range:

    def __init__(self, sheet, srow, erow, scol, ecol):
        self.sheet = sheet
        self.srow = srow
        self.erow = erow
        self.scol = scol
        self.ecol = ecol

    @property
    def value(self):
        return [cell.value for cell in self.get_all_cells()]

    @value.setter
    def value(self, v):
        for cell in self.get_all_cells():
            cell.value = v

    @property
    def formula(self):
        return [cell.formula for cell in self.get_all_cells()]

    @formula.setter
    def formula(self, f):
        for cell in self.get_all_cells():
            cell.formula = f

    def __str__(self):
        return f'<Range at {self.sheet.name}!${self.scol}${self.srow}:${self.ecol}${self.erow}>'

    def __repr__(self):
        return self.__str__()

    def get_first_cell(self):
        return self.sheet[(self.scol, self.srow)]

    def get_all_cells(self, column=None, row=None):
        assert(column == None) # For now let's keep this disabled..
        cols = [column] if column is not None else range(Cell.convert_to_column_index(self.scol), Cell.convert_to_column_index(self.ecol)+1)

        rows = [self.srow + row] if row is not None else range(self.srow, self.erow+1)
        coordinates = [(Cell.convert_to_column_name(c), r) for c, r in product(cols, rows)]
        return [self.sheet[c, r] for c, r in coordinates]


class Cell:
    """
    Represents a cell, with metadata, value, formula, and a next() method that is used during the macro execution
    """
    # XXX we can refactor this in: sheetname = '<sheetname>'; a1_addr_regex = sheetname + '<column>..<row>'
    _a1_cell_addr_regex_str = r"((?P<sheetname>[^\s]+?|'.+?')!)?\$?(?P<column>[a-zA-Z]+)\$?(?P<row>\d+)"
    _a1_cell_addr_regex = re.compile(_a1_cell_addr_regex_str)

    _r1c1_abs_cell_addr_regex_str = r"((?P<sheetname>[^\s]+?|'.+?')!)?R(?P<row>\d+)C(?P<column>\d+)"
    _r1c1_abs_cell_addr_regex = re.compile(_r1c1_abs_cell_addr_regex_str)

    _r1c1_cell_addr_regex_str = r"((?P<sheetname>[^\s]+?|'.+?')!)?R(\[?(?P<row>-?\d+)\]?)?C(\[?(?P<column>-?\d+)\]?)?"
    _r1c1_cell_addr_regex = re.compile(_r1c1_cell_addr_regex_str)

    _range_addr_regex_str = r"((?P<sheetname>[^\s]+?|'.+?')[!|$])?\$?(?P<column1>[a-zA-Z]+)\$?(?P<row1>\d+)\:?\$?(?P<column2>[a-zA-Z]+)\$?(?P<row2>\d+)"
    _range_addr_regex = re.compile(_range_addr_regex_str)

    # "'Sales Data'!$1:$3"
    _range_addr_regex_row_str = r"((?P<sheetname>[^\s]+?|'.+?')[!|$])?\$?(?P<row1>\d+)\:\$?(?P<row2>\d+)"
    _range_addr_regex_row = re.compile(_range_addr_regex_row_str)

    # "'Sales Data'!$a:$a"
    _range_addr_regex_col_str = r"((?P<sheetname>[^\s]+?|'.+?')[!|$])?\$?(?P<column1>[a-zA-Z]+)\:\$?(?P<column2>[a-zA-Z]+)"
    _range_addr_regex_col = re.compile(_range_addr_regex_col_str)

    def __init__(self):
        self.sheet = None
        self.column = ''
        self.row = 0
        self._formula = None
        self._value = None
        self.attributes = {}

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def formula(self):
        return self._formula

    @formula.setter
    def formula(self, formula):
        self._formula = formula

    @property
    def successors(self):
        for i in range(1, MAX_ROWS - self.row):
            cell = self.sheet.cells.get((self.column, self.row+i))
            if cell:
                yield cell

        # successors = [c for k, c in self.sheet.items() if k[0] == self.column and k[1] > self.row]

    def next(self):
        """
        Lazy lookup next cell (don't walk empty cells that are not in memory)
        """
        try:
            return next(self.successors)
        except StopIteration:
            return None

    def __deepcopy__(self, sheet):
        copy = Cell()
        copy.sheet = sheet
        copy.column = self.column
        copy.row = self.row
        copy.formula = self.formula
        copy.value = self.value
        copy.attributes = self.attributes
        return copy

    def get_local_address_string(self):
        return self.column + str(self.row)

    def __lt__(self, other):
        if other is None:
            return True
        if self.column_index == other.column_index:
            return self.row < other.row
        return self.column_index < other.column_index

    def get_local_address_pair(self):
        return self.column, self.row

    @property
    def column_index(self):
        return Cell.convert_to_column_index(self.column)

    @property
    def coordinates(self):
        return self.sheet.name, self.column, self.row

    @property
    def a1(self):
        return '%s!$%s$%s' % (self.sheet.name, self.column, self.row)

    @property
    def r1c1(self):
        return '%s!R%sC%s' % (self.sheet.name, self.convert_to_column_index(self.column), self.row)

    def __str__(self):
        return f'<Cell at {self.get_local_address_string()}>'

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def convert_to_column_index(s):
        number = 0
        power = 1
        for character in reversed(s):
            character = character.upper()
            digit = ((ord(character) - ord('A')) + 1) * power
            number = number + digit
            power = power * 26

        return number

    @staticmethod
    def convert_to_column_name(n):
        string = ""
        while n > 0:
            n, remainder = divmod(n - 1, 26)
            string = chr(ord('A') + remainder) + string
        return string

    @staticmethod
    def parse_cell_addr(cell_addr_str):
        cell_addr_str = cell_addr_str.strip('\"')
        alternate_res = Cell._r1c1_abs_cell_addr_regex.match(cell_addr_str)
        if alternate_res is not None:
            sheet_name = alternate_res.group('sheetname')
            sheet_name = sheet_name.strip('\'') if sheet_name is not None else sheet_name
            column = Cell.convert_to_column_name(int(alternate_res.group('column')))
            row = alternate_res.group('row')
            return sheet_name, column, int(row)
        else:
            res = Cell._a1_cell_addr_regex.match(cell_addr_str)
            if res is not None:
                sheet_name = res.group('sheetname')
                sheet_name = sheet_name.strip('\'') if sheet_name is not None else sheet_name
                column = res.group('column')
                row = res.group('row')
                return sheet_name, column, int(row)
            else:
                return None, None, None

    @staticmethod
    def parse_range_addr(range_addr_str):
        res = Cell._range_addr_regex.match(range_addr_str)
        if res is not None:
            sheet_name = res.group('sheetname')
            sheet_name = sheet_name.strip('\'') if sheet_name is not None else sheet_name
            startcolumn = res.group('column1')
            startrow = res.group('row1')
            endcolumn = res.group('column2')
            endrow = res.group('row2')
            return sheet_name, startcolumn, startrow, endcolumn, endrow

        res = Cell._range_addr_regex_row.match(range_addr_str)
        if res is not None:
            sheet_name = res.group('sheetname')
            sheet_name = sheet_name.strip('\'') if sheet_name is not None else sheet_name
            startcolumn = 'A'
            startrow = res.group('row1')
            endrow   = res.group('row2')
            endcolumn = 'XFD' # Might be smaller to certain files
            return sheet_name, startcolumn, startrow, endcolumn, endrow

        res = Cell._range_addr_regex_col.match(range_addr_str)
        if res is not None:
            sheet_name = res.group('sheetname')
            sheet_name = sheet_name.strip('\'') if sheet_name is not None else sheet_name
            startcolumn = res.group('column1')
            startrow = 1
            endrow   = MAX_ROWS # Might be smaller to certain files
            endcolumn = res.group('column2')
            return sheet_name, startcolumn, startrow, endcolumn, endrow

        return None, None, None, None, None

    @staticmethod
    def convert_twip_to_point(twips):
        # A twip is 1/20 of a point
        point = int(twips) * 0.05
        return point
