import ast
import logging
import math
import re
from collections import defaultdict, deque
from typing import Dict, List, TYPE_CHECKING

import lark
import z3

from symbexcel.excel_wrapper import COMWrapper
from .abstract import AbstractChar, AbstractDataType, AbstractDatetime, AbstractString, Solver
from .boundsheet import Boundsheet, Cell, Range
from .config import *
from .fs import FileSystem

if TYPE_CHECKING:
    from simulation_manager import SimulationManager

log = logging.getLogger(__name__)


class State:
    def __init__(self, simgr: 'SimulationManager', curr_cell: Cell, memory: Dict[str, Boundsheet], defined_names: dict = None,
                 solver: Solver = None, environment: dict = None, dconn_processed: bool = None, detected_symbolic_args: list = None):
        self.simgr = simgr
        self.curr_cell = curr_cell  # next executing cell, starts at auto_open
        self.memory = memory
        self.defined_names = defined_names or self.simgr.excel_doc.get_defined_names()
        self.fs = FileSystem()

        self.dconn_processed = dconn_processed or False
        self.detected_symbolic_args = detected_symbolic_args or list()

        self.history = deque([], self.simgr.keep_predecessors)
        self.halt = False
        self.error = None

        self.register = {}
        self.solver = solver or Solver()

        self.environment = environment
        if self.environment is None:
            self.init_environment()

        self.if_stack = []
        self.subroutine_stack = []
        self.while_stack = dict()

        self._handlers = defaultdict()
        self.init_handlers()

        self.handlers_log =  []
        self.formula_log  =  []
        self.iocs = []

        # init dconn
        if self.dconn_processed == False:
            for i, conn in enumerate(self.simgr.dconn):
                if conn in self.defined_names:
                    range = self.defined_names[conn]
                    log.info(f'Writing symbolic value to DCONN cells in range {range}')
                    for j, cell in enumerate(range.get_all_cells()):
                        cell.value = self.solver.get_abstract_var(z3.String, prefix=f'dconn_{i}_cell_{j}')
                        self.simgr.dconn_cells += [cell.coordinates]
                else:
                    log.warning(f'Unable to find DCONN memory range ({conn})')
            self.dconn_processed = True



    def __copy__(self):
        # copy memory
        memory = {k: v.__deepcopy__() for k, v in self.memory.items()}

        # copy defined names
        defined_names = dict()
        for k, v in self.defined_names.items():
            if isinstance(v, Cell):
                sheet, col, row = v.coordinates
                defined_names[k] = memory[sheet][(col, row)]
            elif isinstance(v, Range):
                vv = Range(memory[v.sheet.name], v.srow, v.erow, v.scol, v.ecol)
                defined_names[vv] = vv
            else:
                defined_names[k] = v

        # translate curr_cell to execute in the copied memory
        sheet, col, row = self.curr_cell.coordinates
        curr_cell = memory[sheet][(col, row)]

        # translate/deepcopy the solver
        solver = self.solver.__deepcopy__()

        copy = State(simgr=self.simgr, curr_cell=curr_cell, memory=memory,
                     defined_names=defined_names, solver=solver,
                     environment=self.environment, dconn_processed=self.dconn_processed,
                     detected_symbolic_args=self.detected_symbolic_args)

        copy.history = self.history.copy()
        copy.halt  = self.halt
        copy.error = self.error

        # copy the if/while/subroutine stacks
        copy.if_stack = self.if_stack.copy()
        copy.subroutine_stack = self.subroutine_stack.copy()
        copy.while_stack = self.while_stack.copy()

        copy.handlers_log = list(self.handlers_log)
        copy.formula_log = list(self.formula_log)
        copy.iocs = list(self.iocs)

        return copy

    def __str__(self):
        if self.error:
            return f'<Errored State at {self.address}>'
        return f'<State at {self.address}>'

    def __repr__(self):
        return self.__str__()

    def __setstate__(self, state):
        self.__dict__ = state
        self.init_handlers()

    def init_handlers(self):
        self._handlers = dict()
        self._handlers.update({
            # methods
            'GET.CELL': self.get_cell_handler,
            'GET.WORKSPACE': self.get_workspace_handler,
            'GET.WORKBOOK': self.get_workbook_handler,
            'GET.NOTE': self.get_note_handler,
            'GET.WINDOW': self.get_window_handler,
            'GET.DOCUMENT': self.get_document_handler,

            # functions
            'ABSREF': self.absref_handler,
            'ACTIVATE': self.activate_handler,
            'ADDRESS': self.address_handler,
            'AVERAGE': self.average_handler,
            'ALERT': self.alert_handler,
            'ABS': self.abs_handler,
            'AND': self.and_handler,
            'APP.MAXIMIZE': self.app_maximize_handler,
            'ASIN': self.asin_handler,
            'ACOS': self.acos_handler,
            'CALL': self.call_handler,
            'CANCEL.KEY': self.cancel_key_handler,
            'CEILING.PRECISE': self.ceiling_precise_handler,
            'CHAR': self.char_handler,
            'CLOSE': self.halt_handler,
            'CONCATENATE': self.concatenate_handler,
            'COS': self.cos_handler,
            'CODE': self.code_handler,
            'COUNT': self.count_handler,
            'COUNTA': self.counta_handler,
            'COUNTBLANK': self.countblank_handler,
            'DAY': self.day_handler,
            'DOCUMENTS': self.documents_handler,
            'DEFINE.NAME': self.define_name_handler,
            'ELSE.IF': self.elseif_handler,
            'ELSE': self.else_handler,
            'END.IF': self.endif_handler,
            'ERROR': self.error_handler,
            'EXEC': self.exec_handler,
            'FREAD': self.fread_handler,
            'FOPEN': self.fopen_handler,
            'FACT': self.fact_handler,
            'FSIZE': self.fsize_handler,
            'FCLOSE': self.fclose_handler,
            'FWRITELN': self.fwriteln_handler,
            'FWRITE': self.fwrite_handler,
            'FORMULA': self.formula_handler,
            'FORMULA.FILL': self.formula_handler,
            'FORMULA.ARRAY': self.formula_handler,
            'FPOS': self.fpos_handler,
            'FILE.DELETE': self.file_delete_handler,
            'FILES': self.files_handler,
            'GOTO': self.goto_handler,
            'HALT': self.halt_handler,
            'HLOOKUP': self.hlookup_handler,
            'IF': self.if_handler,
            'INDEX': self.index_handler,
            'INT': self.int_handler,
            'INDIRECT': self.indirect_handler,
            'ISERROR': self.iserror_handler,
            'ISNUMBER': self.isnumber_handler,
            'LOWER': self.lower_handler,
            'LEN': self.len_handler,
            'MAX': self.max_handler,
            'MESSAGE': self.message_handler,
            'MIN': self.min_handler,
            'MID': self.mid_handler,
            'MOD': self.mod_handler,
            'NEXT': self.next_handler,
            'NOW': self.now_handler,
            'NOT': self.not_handler,
            'OFFSET': self.offset_handler,
            'ON.TIME': self.on_time_handler,
            'OR': self.or_handler,
            'PAUSE': self.pause_handler,
            'PI': self.pi_handler,
            'PROPER': self.proper_handler,
            'RANDBETWEEN': self.randbetween_handler,
            'RADIANS': self.radians_handler,
            'REGISTER': self.register_handler,
            'REPLACE': self.replace_handler,
            'RETURN': self.return_handler,
            'ROWS': self.rows_handler,
            'ROUNDUP': self.roundup_handler,
            'RUN': self.run_handler,
            'RAND': self.rand_handler,
            'RIGHT': self.right_handler,
            'LEFT': self.left_handler,
            'RESET.TOOLBAR': self.reset_toolbar_handler,
            'SAVE': self.save_handler,
            'SAVE.COPY.AS': self.save_copy_as_handler,
            'SET.NAME': self.set_name_handler,
            'SET.VALUE': self.set_value_handler,
            'SEARCH': self.search_handler,
            'SIN': self.sin_handler,
            'SUM': self.sum_handler,
            'SUMPRODUCT': self.sumproduct_handler,
            'SUMXMY2': self.sumxmy2_handler,
            'T': self.t_handler,
            'TEXT': self.text_handler,
            'TRIM': self.trim_handler,
            'TRUNC': self.trunc_handler,
            'VALUE': self.value_handler,
            'WHILE': self.while_handler,
            'WORKBOOK.HIDE': self.workbook_hide_handler,
            'WORKBOOK.UNHIDE': self.workbook_unhide_handler,
            'WAIT': self.wait_handler,
        })

    def init_environment(self):
        self.environment = dict()
        for name, env in [('workspace', WORKSPACE), ('window', WINDOW), ('cell_info', CELL), ('document', DOCUMENT)]:
            self.environment[name] = dict()
            for i, var in env.items():
                self.environment[name][i] = Solver.get_abstract_var(var['type'], prefix=name)

    def init_datetime(self):
        if 'datetime.now' in self.environment:
            return

        # init datetime.now
        datetime = AbstractDatetime()
        for constraint in datetime.get_constraints():
            self.solver.add(constraint)
        self.environment['datetime.now'] = datetime

    @property
    def address(self):
        if self.curr_cell is None:
            address = 'NA'
        else:
            address = self.curr_cell.a1

        return address

    @property
    def value(self):
        if self.curr_cell is None:
            value = None
        else:
            value = self.curr_cell.value

        return value

    @property
    def formula(self):
        if self.curr_cell is None:
            formula = None
        else:
            formula = self.curr_cell.formula

        return formula

    def create_new_branch(self, constraints: List[z3.BoolRef]) -> 'State':
        # create a new branch with the inverted condition
        branch = self.__copy__()

        for c in constraints:
            branch.solver.add(c)

        # step to the next cell
        # branch.curr_cell = branch.curr_cell.next()

        # add the new branch to the simulation manager
        self.simgr.active.append(branch)

        return branch

    def enter_subroutine(self, entry_point: Cell):
        assert isinstance(entry_point, Cell)

        # push the current coordinates into the subroutine stack
        sheet, col, row = self.curr_cell.coordinates
        self.subroutine_stack.append((sheet, col, row+1))

        # redirect control flow to the new subroutine
        self.curr_cell = entry_point

    def append_ioc(self, handler, ioc):
        if not isinstance(ioc, list):
            ioc = [ioc]

        symbolic = False
        for idx, value in enumerate(ioc):
            if AbstractDataType.is_abstract(value):
                ioc[idx] = list(self.solver.eval_one_expression(value).values())[0]
                symbolic = True

        s = '%s: %s %s' % (handler, ioc, 'SYMBOLIC' if symbolic else '')
        self.iocs.append(s)

    def concretize_cell(self, cell):
        assert cell.formula == cell.value
        log.debug(f'Concretizing cell {cell}')
        self.simgr.symbolic = True
        if not self.handlers_log[-1].startswith('*'):
            self.handlers_log[-1] = '*' + self.handlers_log[-1]

        solutions = self.solver.eval_all_expression(cell.formula, verifier=self.simgr.xlm_parser.parse)

        if len(solutions) == 0:
            raise RuntimeError('Unable to find a parsable solution')

        # if there are more solutions, create one branch per solution
        if len(solutions) > 1:
            # skip the first solution because it'll be processed in the current branch
            for model in list(solutions.keys())[1:]:
                # get the constraints from the current model
                constraints = self.solver.get_all_constraints(cell.formula, model)
                # create a new branch (with the correct constraints)
                new_branch = self.create_new_branch(constraints)
                # make its curr_cell.formula concrete (fixed to the current solution)
                new_branch.curr_cell.formula = solutions[model]

        # process the first solution in the current branch
        model = list(solutions.keys())[0]
        constraints = self.solver.get_all_constraints(cell.formula, model)

        # set the current formula and value to the concrete solution
        cell.formula = cell.value = solutions[model]

        # add the constraints to the solver
        for c in constraints:
            self.solver.add(c)

    def concretize_defined_name(self, name):
        log.debug(f'Concretizing name {name}')
        self.simgr.symbolic = True
        if not self.handlers_log[-1].startswith('*'):
            self.handlers_log[-1] = '*' + self.handlers_log[-1]

        solutions = self.solver.eval_all_expression(self.defined_names[name.lower()], verifier=self.simgr.xlm_parser.parse)

        if len(solutions) == 0:
            raise RuntimeError('Unable to find a parsable solution')

        # if there are more solutions, create one branch per solution
        if len(solutions) > 1:
            # skip the first solution because it'll be processed in the current branch
            for model in list(solutions.keys())[1:]:
                # get the constraints from the current model
                constraints = self.solver.get_all_constraints(self.defined_names[name.lower()], model)
                # create a new branch (with the correct constraints)
                new_branch = self.create_new_branch(constraints)
                # make its curr_cell.formula concrete (fixed to the current solution)
                new_branch.defined_names[name.lower()] = solutions[model]

        # process the first solution in the current branch
        model = list(solutions.keys())[0]
        constraints = self.solver.get_all_constraints(self.defined_names[name.lower()], model)

        # set the current formula and value to the concrete solution
        self.defined_names[name.lower()] = solutions[model]

        # add the constraints to the solver
        for c in constraints:
            self.solver.add(c)

    def explode_parse_tree(self, parse_tree, parent_type=None):
        # log.debug(parse_tree)
        if not isinstance(parse_tree, lark.Tree) and parse_tree.type == 'NAME' \
                and parent_type not in ['function_call', 'defined_name']:
            # log.debug(f'got type: {type(parse_tree)} ({parse_tree.type}:::{parse_tree})')
            name  = parse_tree.value
            value = self.get_defined_name(self.curr_cell, name)
            if isinstance(value, str) and value.startswith('='):
                # log.debug(f'exploding name {name}')
                parse_tree = self.simgr.xlm_parser.parse(value)
                # parse away the "start" node
                parse_tree = parse_tree.children[0]

                # explode recursively
                parse_tree = self.explode_parse_tree(parse_tree)
            return parse_tree
        if not isinstance(parse_tree, lark.Tree):
            return parse_tree
        elif len(parse_tree.children) > 0:
            parent_type = parse_tree.data
            return lark.Tree(parent_type, [self.explode_parse_tree(tree, parent_type) for tree in parse_tree.children])

    def find_accessed(self, parse_tree, parent_type=None):
        accessed = dict({
            'cells': dict(),
            'names': dict(),
        })

        # match name (not for function calls)
        if isinstance(parse_tree, lark.Token) and parse_tree.type == 'NAME' and parent_type != 'function_call':
            name = parse_tree.value.lower()
            value = self.get_defined_name(self.curr_cell, name)
            accessed['names'][name] = value
            if isinstance(value, str) and value.startswith('='):
                parse_tree = self.simgr.xlm_parser.parse(value)
                # parse away the "start" node
                parse_tree = parse_tree.children[0]
                children_accessed = self.find_accessed(parse_tree)
                accessed['names'].update(children_accessed['names'])
                accessed['cells'].update(children_accessed['cells'])
        # match cell
        elif isinstance(parse_tree, lark.Tree) and parse_tree.data == 'cell':
            sheet, col, row = self.get_cell_addr(self.curr_cell, parse_tree)
            cell = self.memory[sheet][(col, row)]
            value = AbstractDataType.unwrap_operand(self, cell)
            accessed['cells'][cell.a1] = (sheet, col, row, cell.formula, value)
        # match range
        elif isinstance(parse_tree, lark.Tree) and parse_tree.data == 'range':
            sheet, scol, srow = self.get_cell_addr(self.curr_cell, parse_tree.children[0])
            _, ecol, erow = self.get_cell_addr(self.curr_cell, parse_tree.children[2])
            range = self.memory[sheet][(scol, srow):(ecol, erow)]
            for cell in range.get_all_cells():
                value = AbstractDataType.unwrap_operand(self, cell)
                accessed['cells'][cell.a1] = (cell.sheet.name, cell.column, cell.row, cell.formula, value)
        elif isinstance(parse_tree, lark.Tree):
            parent_type = parse_tree.data
            for c in parse_tree.children:
                children_accessed = self.find_accessed(c, parent_type)
                accessed['names'].update(children_accessed['names'])
                accessed['cells'].update(children_accessed['cells'])

        return accessed

    def find_control_flow(self, parse_tree):
        control_flow = {
            'handlers': set(),
            'other': set()
        }

        if isinstance(parse_tree, lark.Tree) and parse_tree.data == 'function_call':
            function = parse_tree.children[0]
            if isinstance(function, str) and function not in self.register:
                control_flow['handlers'].add(function)
            else:
                control_flow['other'].add(function)
        elif isinstance(parse_tree, lark.Tree):
            for c in parse_tree.children:
                children_control_flow = self.find_control_flow(c)
                control_flow['handlers'].update(children_control_flow['handlers'])
                control_flow['other'].update(children_control_flow['other'])

        return control_flow

    def has_symbolic_arguments(self, parse_tree, parent_type=None):
        # match name (not for function calls)
        if isinstance(parse_tree, lark.Token) and parse_tree.type == 'NAME' and parent_type != 'function_call':
            name  = parse_tree.value
            value = self.get_defined_name(self.curr_cell, name)
            unwrapped_cell = AbstractDataType.unwrap_operand(self, value)
            if AbstractDataType.is_abstract(unwrapped_cell):
                return True
        # match cell
        elif isinstance(parse_tree, lark.Tree) and parse_tree.data == 'cell':
            sheet, col, row = self.get_cell_addr(self.curr_cell, parse_tree)
            cell = self.memory[sheet][(col, row)]
            unwrapped_cell = AbstractDataType.unwrap_operand(self, cell)
            if AbstractDataType.is_abstract(unwrapped_cell):
                return True
        # match range
        elif isinstance(parse_tree, lark.Tree) and parse_tree.data == 'range':
            sheet, scol, srow = self.get_cell_addr(self.curr_cell, parse_tree.children[0])
            _, ecol, erow = self.get_cell_addr(self.curr_cell, parse_tree.children[2])
            range = self.memory[sheet][(scol, srow):(ecol, erow)]
            if any(AbstractDataType.is_abstract(v) for v in range.value):
                return True
        elif isinstance(parse_tree, lark.Tree):
            parent_type = parse_tree.data
            for c in parse_tree.children:
                if self.has_symbolic_arguments(c, parent_type):
                    return True

        return False

    def convert_parse_tree_to_r1c1(self, parse_tree):
        if isinstance(parse_tree, lark.Tree) and parse_tree.data == 'a1_notation_cell':
            if len(parse_tree.children) == 2:
                cell_addr = "'{}'!{}".format(parse_tree.children[0], parse_tree.children[1])
            else:
                cell_addr = parse_tree.children[0]
            sheet, col, row = Cell.parse_cell_addr(cell_addr)
            sheet = sheet or self.curr_cell.sheet.name
            col = Cell.convert_to_column_index(col)
            return lark.Tree('r1c1_notation_cell', [
                lark.Token('NAME', sheet),
                lark.Token('ROW', 'R'),
                lark.Token('REF', row),
                lark.Token('COL', 'C'),
                lark.Token('REF', col)
            ])
        elif isinstance(parse_tree, lark.Tree) and parse_tree.data == 'r1c1_notation_cell':
            if parse_tree.children[1].type != 'EXCLAMATION':
                sheet = self.curr_cell.sheet.name
                parse_tree.children = [lark.Token('NAME', sheet), lark.Token('EXCLAMATION', '!')] + parse_tree.children
            return parse_tree
        elif isinstance(parse_tree, lark.Tree):
            return lark.Tree(parse_tree.data, [self.convert_parse_tree_to_r1c1(c) for c in parse_tree.children])
        else:
            return parse_tree

    def parse_tree_to_formula(self, parse_tree):
        if isinstance(parse_tree, lark.Token):
            return parse_tree.value
        elif isinstance(parse_tree, lark.Tree):
            prefix = '=' if parse_tree.data == 'start' else ''
            return prefix+''.join([self.parse_tree_to_formula(c) for c in parse_tree.children])
        elif parse_tree is None:
            return ''
        else:
            log.error(f'cannot parse {type(parse_tree)}')
            raise NotImplementedError

    def step(self) -> None:
        # read the current instruction
        curr_cell = self.curr_cell

        log.debug(f'Stepping {self} [{self.simgr}]')
        self.handlers_log += ['']

        if curr_cell and curr_cell.coordinates in self.simgr.dconn_cells:
            log.warning('Executing a DCONN instruction')
            self.halt = True
            return

        symbolic = False
        if curr_cell is None:
            log.warning(f'Executing an empty cell {curr_cell}')
            self.halt = True
            return
        elif AbstractDataType.is_abstract(curr_cell.formula):
            log.warning('EXECUTING A SYMBOLIC INSTRUCTION')

            symbolic = True
            self.concretize_cell(curr_cell)

        # if curr_cell.formula is None and curr_cell.value is not None:
        #     curr_cell.formula = curr_cell.value

        if isinstance(curr_cell.formula, str):
            # append a copy of the current state to the execution history (history is a bounded queue)
            if self.history.maxlen != 0:
                copy = self.__copy__()
                copy.simgr = copy.memory = copy.solver = copy.history = copy._handlers = None
                self.history.append(copy)

            # parse and emulate the instruction
            try:
                parse_tree = self.simgr.xlm_parser.parse(curr_cell.formula)
            except:
                log.warning(f'trying to execute an invalid formula: {curr_cell.formula}')
                curr_cell.formula = None
            else:
                log.debug(f'executing formula: [{curr_cell.a1}] {curr_cell.formula}')
                self.formula_log += [
                    f'{"*" if symbolic else ""}[{curr_cell.column}{curr_cell.row}] {curr_cell.formula}']

                curr_cell.value = self.evaluate_parse_tree(curr_cell, parse_tree)
        else:
            log.warning(f'stepping over value: {curr_cell.value}')

        # increment the instruction pointer (if the control flow was not hijacked)
        if curr_cell == self.curr_cell and not self.halt:
            self.curr_cell = curr_cell.next()


    def evaluate_literal(self, value):
        return ast.literal_eval(value)

    def evaluate_string(self, value):
        value = str(value)
        if len(value) > 1 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('""', '"')
        return value

    def evaluate_boolean(self, value):
        return value == 'TRUE'

    def evaluate_name(self, curr_cell, name):
        try:
            value = self.get_defined_name(curr_cell, name)
            if isinstance(value, str) and value.startswith('='):
                parse_tree = self.simgr.xlm_parser.parse(value)
                return self.evaluate_parse_tree(self.curr_cell, parse_tree)
            else:
                return value
        except KeyError:
            log.warning(f'Key "{parse_tree_root.value.lower()}" not in defined names. Returning #NAME?')
            return "#NAME?"
        except lark.exceptions.LarkError:
            log.warning(f'Failed to parse "{value}" as a formula. (Was this an oUNK defined name?)')
            return value[1:]

    def evaluate_array(self, curr_cell, parse_tree_root):
        assert parse_tree_root.children[0].type == 'L_CURLY' and parse_tree_root.children[-1].type == 'R_CURLY'
        return [self.evaluate_parse_tree(curr_cell, c) for c in parse_tree_root.children[1:-1:2]]

    def evaluate_cell(self, curr_cell, parse_tree_root):
        sheet, col, row = self.get_cell_addr(curr_cell, parse_tree_root)
        cell = self.memory[sheet][(col, row)]
            
        return cell

    def evaluate_range(self, curr_cell, parse_tree_root):
        sheet, scol, srow = self.get_cell_addr(curr_cell, parse_tree_root.children[0])
        _    , ecol, erow = self.get_cell_addr(curr_cell, parse_tree_root.children[2])
        cell = self.memory[sheet][(scol,srow):(ecol,erow)]
        return cell

    def evaluate_expression(self, curr_cell, parse_tree_root):
        text_left = None

        for index, child in enumerate(parse_tree_root.children):
            if type(child) is lark.lexer.Token and child.type in ['ADDITIVEOP', 'MULTIOP', 'CMPOP', 'CONCATOP']:
                _operator = AbstractDataType.OPERATORS[str(child)]
                right_arg = parse_tree_root.children[index + 1]
                if type(right_arg) is lark.lexer.Token and right_arg.type in ['SIGN']:
                    sign = +1 if (right_arg.value.count('-') % 2 == 0) else -1

                    right_arg = parse_tree_root.children[index + 2]
                    right_arg_value = self.evaluate_parse_tree(curr_cell, right_arg)
                    right_arg_value = AbstractDataType.unwrap_operand(self, right_arg_value)
                    right_arg_value = AbstractDataType.process_operation(self.solver, sign, right_arg_value, AbstractDataType.OPERATORS['*'])
                else:
                    right_arg_value = self.evaluate_parse_tree(curr_cell, right_arg)

                text_left, right_arg_value = AbstractDataType.unwrap_operands(self, text_left, right_arg_value)
                text_left = AbstractDataType.process_operation(self.solver, text_left, right_arg_value, _operator)
            elif text_left is None:
                left_arg = parse_tree_root.children[index]
                if type(left_arg) is lark.lexer.Token and left_arg.type in ['SIGN']:
                    sign = +1 if (left_arg.value.count('-') % 2 == 0) else -1

                    left_arg = parse_tree_root.children[index + 1]
                    left_arg_value = self.evaluate_parse_tree(curr_cell, left_arg)
                    left_arg_value = AbstractDataType.unwrap_operand(self, left_arg_value)
                    left_arg_value = AbstractDataType.process_operation(self.solver, sign, left_arg_value, AbstractDataType.OPERATORS['*'])
                else:
                    left_arg_value = self.evaluate_parse_tree(curr_cell, left_arg)
                text_left = left_arg_value

        return text_left

    def evaluate_parse_tree(self, curr_cell: Cell, parse_tree_root):

        if type(parse_tree_root) is lark.lexer.Token:
            if parse_tree_root.type == 'NUMBER':
                return self.evaluate_literal(parse_tree_root.value)
            elif parse_tree_root.type == 'STRING':
                return self.evaluate_string(parse_tree_root.value)
            elif parse_tree_root.type == 'BOOLEAN':
                return self.evaluate_boolean(parse_tree_root.value)
            elif parse_tree_root.type == 'NAME':
                return self.evaluate_name(curr_cell, parse_tree_root.value)
            elif parse_tree_root.type == 'L_CURLY':
                pass
            else:
                raise TypeError(f'Unsupported Token type: {parse_tree_root.type}')

        elif type(parse_tree_root) is list:
            if len(parse_tree_root) == 0:
                return []
            else:
                raise NotImplementedError
        elif not isinstance(parse_tree_root, lark.Tree):
            return parse_tree_root
        elif parse_tree_root.data == 'array':
            return self.evaluate_array(curr_cell, parse_tree_root)
        elif parse_tree_root.data == 'function_call':
            return self.evaluate_function(curr_cell, parse_tree_root)
        elif parse_tree_root.data == 'assignment':
            return self.evaluate_assignment(curr_cell, parse_tree_root)
        elif parse_tree_root.data == 'cell':
            return self.evaluate_cell(curr_cell, parse_tree_root)
        elif parse_tree_root.data == 'range':
            return self.evaluate_range(curr_cell, parse_tree_root)
        elif parse_tree_root.data in ['expression', 'concat_expression', 'additive_expression', 'multiplicative_expression']:
            return self.evaluate_expression(curr_cell, parse_tree_root)
        elif parse_tree_root.data == 'final':
            arg = parse_tree_root.children[1]
            return self.evaluate_parse_tree(curr_cell, arg)
        else:
            for child_node in parse_tree_root.children:
                if child_node is not None:
                    return self.evaluate_parse_tree(curr_cell, child_node)

    def get_defined_name(self, curr_cell, name):
        name = name.lower()
        full_name = curr_cell.sheet.name.lower() + '!' + name
        if name in self.defined_names:
            return self.defined_names.get(name)
        else:
            return self.defined_names.get(full_name)

    def evaluate_function(self, curr_cell: Cell, parse_tree_root):
        function = parse_tree_root.children[0]

        arguments = []
        for i in parse_tree_root.children[2].children:
            if type(i) is not lark.lexer.Token:
                if len(i.children) > 0:
                    arguments.append(i.children[0])
                else:
                    arguments.append(i.children)

        # match registered functions
        if function in self.register:
            return self.handle_registered_function(function, arguments, curr_cell)

        # match function handlers
        if isinstance(function, str) and function.upper() in self._handlers:
            handler = self._handlers[function.upper()]
            hname   = handler.__name__
            # log.debug('[%s]' % hname)
            self.handlers_log[-1] += '_[%s]' % hname.replace('_handler', '')

            if self.simgr.check_symbolic_args and hname.replace("_handler", "").upper() not in self.detected_symbolic_args:
                exploded_parse_tree = self.explode_parse_tree(parse_tree_root)
                if self.has_symbolic_arguments(exploded_parse_tree):
                    log.info(f'DETECTED SYMBOLIC ARGUMENTS ({hname.replace("_handler", "").upper()})')
                    self.detected_symbolic_args += [hname.replace("_handler", "").upper()]

            return handler(arguments, curr_cell)

        # match defined names
        if isinstance(function, lark.Tree) and function.data == 'defined_name':
            # calling a defined name will create a new subroutine and redirect the control flow
            entry_point = self.evaluate_parse_tree(curr_cell, function.children[-1])
            return self.enter_subroutine(entry_point)

        # match names
        if isinstance(function, lark.Token) and function.type == 'NAME':
            # calling a defined name will create a new subroutine and redirect the control flow
            func_name   = function.value
            entry_point = self.get_defined_name(curr_cell, func_name)
            if entry_point:
                return self.enter_subroutine(entry_point)

        # match cell
        if isinstance(function, lark.Tree) and function.data == 'cell':
            assert arguments == [[]]

            sheet, col, row = self.get_cell_addr(curr_cell, function)
            entry_point = self.memory[sheet][(col, row)]

            return self.enter_subroutine(entry_point)

        # match range
        if isinstance(function, lark.Tree) and function.data == 'range':
            assert arguments == [[]]

            # jump to the first cell in the range
            sheet, col, row = self.get_cell_addr(curr_cell, function.children[0])
            entry_point = self.memory[sheet][(col, row)]

            return self.enter_subroutine(entry_point)

        # else dispatch to the default handler
        else:
            return self.default_handler(curr_cell, parse_tree_root)

    def evaluate_assignment(self, curr_cell: Cell, parse_tree_root):
        name = parse_tree_root.children[0]
        assert isinstance(name, lark.Token) and name.type == 'NAME'
        name = name.value.lower()

        value = self.evaluate_parse_tree(curr_cell, parse_tree_root.children[1])
        if isinstance(value, str):
            value = value.replace('"', '""')
            value = f'="{value}"'
        self.defined_names[name] = value

        return True

    def handle_registered_function(self, macro_name, arguments, curr_cell):
        module, function, retvalue = self.register[macro_name]
        args = [self.evaluate_parse_tree(curr_cell, arg) for arg in arguments]
        args = AbstractDataType.unwrap_operands(self, *args)

        log.debug(f"Calling registered function {macro_name}: {module}.{function}({args})")

        self.append_ioc('REGISTER', [f'{module}.{function}'] + args)

        # XXX: here we should turn a proper return value, depending on 'type_text' of REGISTER
        return Solver.get_abstract_var(z3.Bool, prefix='return_%s' % macro_name)

    # XXX: shouldn't this function be part of evaluate_parse_tree?
    def get_cell_addr(self, curr_cell: Cell, cell_parse_tree):
        res_sheet = res_col = res_row = None
        if type(cell_parse_tree) is lark.lexer.Token:
            label = cell_parse_tree.value.lower()
            if label in self.defined_names:
                cell = self.defined_names[label]
                res_sheet, res_col, res_row = cell.coordinates
            elif label.strip('"') in self.defined_names:
                cell = self.defined_names[label.strip('"')]
                res_sheet, res_col, res_row = cell.coordinates
            else:
                if len(label) > 1 and label.startswith('"') and label.endswith('"'):
                    label = label.strip('"')
                    root_parse_tree = self.simgr.xlm_parser.parse('=' + label)
                    res_sheet, res_col, res_row = self.get_cell_addr(curr_cell, root_parse_tree.children[0])

        elif type(cell_parse_tree) is lark.Tree and cell_parse_tree.data == 'range':
            sheet, scol, srow = self.get_cell_addr(curr_cell, cell_parse_tree.children[0])
            _    , ecol, erow = self.get_cell_addr(curr_cell, cell_parse_tree.children[2])
            assert(scol == ecol and srow == erow)
            return sheet, scol, srow

        elif type(cell_parse_tree) is lark.Tree and cell_parse_tree.data == 'defined_name':
            cell = self.evaluate_parse_tree(curr_cell, cell_parse_tree.children[-1])
            sheet = cell_parse_tree.children[0] if len(cell_parse_tree.children) > 1 else self.curr_cell.sheet.name
            if cell:
                col, row = cell.get_local_address_pair()
                return sheet, col, row
            else:
                raise RuntimeError('Trying to access an invalid defined name')

        elif type(cell_parse_tree) is lark.Tree:
            cell = cell_parse_tree.children[0]

            if cell.data == 'a1_notation_cell':
                if len(cell.children) == 1:
                    cell_addr = cell.children[0]
                elif cell.children[0].type == 'EXCLAMATION':
                    cell_addr = "'{}'!{}".format(curr_cell.sheet.name, cell.children[-1])
                elif cell.children[0].type == 'NAME':
                    cell_addr = "'{}'!{}".format(cell.children[0], cell.children[-1])
                else:
                    cell_addr = "'{}'!{}".format(cell.children[1], cell.children[-1])
                res_sheet, res_col, res_row = Cell.parse_cell_addr(cell_addr)

                if res_sheet is None and res_col is not None:
                    res_sheet = curr_cell.sheet.name

            elif cell.data == 'r1c1_notation_cell':
                current_col = Cell.convert_to_column_index(curr_cell.column)
                current_row = int(curr_cell.row)

                last_seen = None
                for current_child in cell.children:
                    if current_child.type == 'NAME':
                        res_sheet = current_child.value
                    elif isinstance(current_child.value, float):
                        val = int(float(current_child.value))
                        if last_seen == 'r':
                            res_row = val
                        else:
                            res_col = val

                    elif current_child.type == 'INT':
                        val = int(current_child.value)
                        if last_seen == 'r':
                            res_row = val
                        else:
                            res_col = val

                    elif current_child.value.startswith('['):
                        val = int(current_child.value[1:-1])
                        if last_seen == 'r':
                            res_row = current_row + val
                        else:
                            res_col = current_col + val
                    elif current_child.lower() == 'r':
                        last_seen = 'r'
                        res_row = current_row
                    elif current_child.lower() == 'c':
                        last_seen = 'c'
                        res_col = current_col
                    elif current_child.type == 'EXCLAMATION':
                        # ignore the exclamation mark when parsing cell address
                        pass
                    elif current_child.type == 'QUOTE':
                        # ignore the quote when parsing cell address
                        pass
                    else:
                        raise Exception('Cell addresss, Syntax Error')

                if res_sheet is None:
                    res_sheet = curr_cell.sheet.name
                # res_row = str(res_row)
                res_col = Cell.convert_to_column_name(res_col)
            else:
                raise Exception(f'Cell addresss, Syntax Error ({cell_parse_tree})')
        else:
            raise Exception(f'Cell addresss, Syntax Error ({cell_parse_tree})')
        return res_sheet, res_col, res_row

    def day_handler(self, arguments: List, curr_cell: Cell):
        datetime = self.evaluate_parse_tree(curr_cell, arguments[0])
        return datetime.day

    def documents_handler(self, arguments: List, curr_cell: Cell):
        num = self.evaluate_parse_tree(curr_cell, arguments[0])
        assert(num == 1)
        # This handler should return the name of a workbook, depending on the num.
        # If only one book is open, then it should be its name.
        return num

    def default_handler(self, curr_cell: Cell, parse_tree):
        function = parse_tree.children[0]
        log.warning(f'Invoking the default handler (function: {function})')

        # check if we should delegate
        delegated = False

        exploded_parse_tree = None
        control_flow = None
        if isinstance(self.simgr.excel_doc, COMWrapper) and self.simgr.enable_delegations:
            exploded_parse_tree = self.explode_parse_tree(parse_tree)
            control_flow = self.find_control_flow(exploded_parse_tree)

        # 1. if we are not using the COM server or delegations are not enabled, don't delegate
        if not isinstance(self.simgr.excel_doc, COMWrapper) or not self.simgr.enable_delegations:
            pass
        # 2. If no handler is executed, don't delegate
        elif len(control_flow['handlers']) == 0:
            pass
        # 3. if all handlers are implemented, don't delegate
        elif all(h.upper() in self._handlers or h.lower() in self.defined_names for h in control_flow['handlers']):
            pass
        # 4. if any handler is implemented, pass (e.g., we don't want to delegate GET.WORKSPACE)
        elif any(h.upper() in self._handlers or h.lower() in self.defined_names for h in control_flow['handlers']):
            # raise NotImplementedError('Unable to delegate a partially implemented formula')
            pass
        # 5. if any handler is not a valid formula or name, raise an exception
        elif any(h.upper() not in XL4_FORMULAS and h.lower() not in self.defined_names for h in control_flow['handlers']):
            raise NotImplementedError(f'Unable to delegate: some of the handlers appear invalid ({[h for h in control_flow["handlers"] if h.upper() not in XL4_FORMULAS and h.lower() not in self.defined_names]})')
        # 6. if there's any control flow instruction, don't delegate
        elif len(control_flow['other']) > 0:
            pass
        # 7. if any leaf node is symbolic, don't delegate
        elif self.has_symbolic_arguments(exploded_parse_tree):
            pass
        # 8. if there is a reference to a vba macro, don't delegate
        elif any(h in self.simgr.vba_code for h in control_flow['handlers']):
            raise NotImplementedError(f'This formula refers to a VBA Macro, aborting.')

        # 9. else, delegate
        else:
            # check if accessing next cell
            accessed = self.find_accessed(parse_tree)
            if f'{curr_cell.sheet.name}!${curr_cell.column}${curr_cell.row + 1}' in accessed['cells']:
                raise NotImplementedError('Unable to delegate a formula referencing the next cell')

            # a. convert to r1c1
            r1c1_tree = self.convert_parse_tree_to_r1c1(parse_tree)
            r1c1_formula = self.parse_tree_to_formula(r1c1_tree)
            # formula = self.parse_tree_to_formula(parse_tree)
            # b. invoke COM server passing formula, context (to sync), and target cells

            try:
                log.info(f'Trying to delegate: {r1c1_formula}')

                # accessed = self.find_accessed(exploded_parse_tree)
                result, new_accessed = self.simgr.excel_doc.execute_formula(curr_cell.sheet.name, curr_cell.column,
                                                                            curr_cell.row, r1c1_formula, accessed)
                log.info(f'Delegated successfully, result is: {result}')
                log.info(f'Updating accessed cells and names..')

                # update accessed cells
                # curr_cell.value = result
                for cell_sheet_name, cell_column, cell_row, cell_formula, cell_value in new_accessed['cells'].values():
                    cell = self.memory[cell_sheet_name][(cell_column, cell_row)]

                    if cell.formula != cell_formula:
                        log.debug(f'Updating cell {cell} -- new formula: {cell_formula}')
                        cell.formula = cell_formula
                    if cell.value != cell_value:
                        log.debug(f'Updating cell {cell} -- new value: {cell_value}')
                        cell.value = cell_value

                # update accessed names
                for name, name_value in new_accessed['names'].items():
                    if self.defined_names[name] != name_value:
                        log.debug(f'Updating defined name {name} -- new value: {name_value}')
                        self.defined_names[name] = name_value

                delegated = True
            except:
                log.error(f'Failed to delegate: {r1c1_formula}')

        if delegated:
            return result
        elif self.simgr.default_handlers:
            log.warning('Returning a default symbolic value')
            return Solver.get_abstract_var(z3.Bool, prefix='default_handler')
        else:
            raise NotImplementedError(f'the formula handler for "{curr_cell.formula}" is not implemented')

    def get_cell_handler(self, arguments: List, curr_cell: Cell):
        index = int(self.evaluate_parse_tree(curr_cell, arguments[0]))
        cell = self.evaluate_parse_tree(curr_cell, arguments[1])

        cell_info = self.simgr.excel_doc.get_cell_info(cell.sheet.name, cell.column, cell.row, index)

        # log.debug('GET_CELL(%d, %s) returns: %f' % (index, cell, cell_info))
        return cell_info or self.environment['cell_info'][index]

    def get_note_handler(self, arguments: List, curr_cell: Cell):
        cell = self.evaluate_parse_tree(curr_cell, arguments[0])
        return self.simgr.excel_doc.get_comments().get(cell.a1)

    def get_workbook_handler(self, arguments: List, curr_cell: Cell):
        index = self.evaluate_parse_tree(curr_cell, arguments[0])
        book   = self.evaluate_parse_tree(curr_cell, arguments[1])
        index = int(AbstractDataType.unwrap_operand(curr_cell, index))
        # For now we ignore the book parameter, and assume that it's the currently loaded Book.
        info  = self.simgr.excel_doc.get_workbook_info(index)
        return info

    def get_window_handler(self, arguments: List, curr_cell: Cell):
        index = int(float(self.evaluate_parse_tree(curr_cell, arguments[0])))

        return self.environment['window'][index]

    def get_document_handler(self, arguments: List, curr_cell: Cell):
        index = int(float(self.evaluate_parse_tree(curr_cell, arguments[0])))
        return self.environment['document'][index]

    def get_workspace_handler(self, arguments: List, curr_cell: Cell):
        index = int(float(self.evaluate_parse_tree(curr_cell, arguments[0])))

        return self.environment['workspace'][index]

    def absref_handler(self, arguments: List, curr_cell: Cell):
        offset = self.evaluate_parse_tree(curr_cell, arguments[0])
        reference_cell = self.evaluate_parse_tree(curr_cell, arguments[1])

        # parse the r1c1 notation cell
        offset_tree = self.simgr.xlm_parser.parse(f"={offset}").children[0]
        result = self.evaluate_parse_tree(reference_cell, offset_tree)

        return result

    def activate_handler(self, arguments: List, curr_cell: Cell):
        window = self.evaluate_parse_tree(curr_cell, arguments[0])
        pane   = self.evaluate_parse_tree(curr_cell, arguments[1])
        return

    def alert_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = AbstractDataType.unwrap_operand(self, value)

        if AbstractDataType.is_abstract(value):
            _, value = list(self.solver.eval_one_expression(value).items())[0]

        log.debug(f'ALERT: {value}')

        return True

    def abs_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = AbstractDataType.unwrap_operand(self, value)

        if AbstractDataType.is_abstract(value):
            return z3.If(value >= 0, value, -value)
        else:
            return abs(value)

    def and_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        if any([AbstractDataType.is_abstract(a) for a in parsed_arguments]):
            observed_value = z3.And([Solver.process_constraint(c) for c in parsed_arguments])
            return self.solver.get_observer(observed_value, prefix='observer_and', z3_type=z3.Bool)

        return all([Solver.process_constraint(c) for c in parsed_arguments])

    def app_maximize_handler(self, arguments: List, curr_cell: Cell):
        return True

    def call_handler(self, arguments: List, curr_cell: Cell):
        args = [self.evaluate_parse_tree(curr_cell, arg) for arg in arguments]
        args = AbstractDataType.unwrap_operands(self, *args)
        self.append_ioc('CALL', args)
        
        return Solver.get_abstract_var(z3.Int, prefix='call_handler')

    def ceiling_precise_handler(self, arguments: List, curr_cell: Cell):
        number = self.evaluate_parse_tree(curr_cell, arguments[0])
        if len(arguments) > 1:
            significance = self.evaluate_parse_tree(curr_cell, arguments[1])
        else:
            significance = 1

        return significance * math.ceil(float(number)/significance)

    def cancel_key_handler(self, arguments: List, curr_cell: Cell):
        # specifies whether the macro can be interrupted by pressing ESC in Microsoft Excel
        return True

    def char_handler(self, arguments: List, curr_cell: Cell):
        target_ascii_value = self.evaluate_parse_tree(curr_cell, arguments[0])
        target_ascii_value = AbstractDataType.unwrap_operand(self, target_ascii_value)

        # excel has an 8 digit precision, add 1e-8 before rounding to int
        if isinstance(target_ascii_value, float) or (isinstance(target_ascii_value, z3.ArithRef) and target_ascii_value.is_real()):
            target_ascii_value += 10 ** -8
            # target_ascii_value = self.roundup_handler([target_ascii_value, 8], curr_cell)

        # if the target ascii is concrete, just return the concrete char
        if AbstractDataType.is_concrete(target_ascii_value):
            try:
                return chr(round(target_ascii_value))
            except:
                self.simgr.set_error('Char not in range(0x110000)')
                return '?'

        if target_ascii_value.is_real():
            target_ascii_value = AbstractDataType.cast_to_int(target_ascii_value)

        # constraint target ascii value to printable range
        self.solver.add(target_ascii_value >= 0x20)
        self.solver.add(target_ascii_value <= 0x7e)

        # solutions = self.solver.eval_all_expression(target_ascii_value)
        # print('solutions:', [chr(int(float(c))) for c in solutions.values()])

        # return the target char with the right constraints
        return AbstractChar(target_ascii_value)

    def countblank_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]

        # unwrap Range arguments
        parsed_arguments = [e for arg in parsed_arguments for e in
                            (arg.get_all_cells() if isinstance(arg, Range) else [arg])]

        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        # count the number of non blank values
        count = 0
        for arg in parsed_arguments:
            if arg is None:
                count += 1

        return count

    def counta_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]

        # unwrap Range arguments
        parsed_arguments = [e for arg in parsed_arguments for e in
                            (arg.get_all_cells() if isinstance(arg, Range) else [arg])]

        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        # count the number of non blank values
        count = 0
        for arg in parsed_arguments:
            if arg is not None:
                count += 1

        return count

    def count_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]

        # unwrap Range arguments
        parsed_arguments = [e for arg in parsed_arguments for e in
                            (arg.get_all_cells() if isinstance(arg, Range) else [arg])]

        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        # count the number of numerical values
        count = 0
        for arg in parsed_arguments:
            if isinstance(arg, (int, float, z3.ArithRef)):
                count += 1

        return count

    def define_name_handler(self, arguments: List, curr_cell: Cell):
        assert len(arguments) == 2

        name  = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = self.evaluate_parse_tree(curr_cell, arguments[1])
        if isinstance(value, str):
            value = value.replace('"', '""')
            value = f'="{value}"'
        self.defined_names[name.lower()] = value
        return True

    def error_handler(self, arguments: List, curr_cell: Cell):
        log.warning('Unsupported custom error handling routines')
        return True

    def file_delete_handler(self, arguments: List, curr_cell: Cell):
        filename = self.evaluate_parse_tree(curr_cell, arguments[0])
        return Solver.get_abstract_var(z3.Bool, prefix='file_delete_handler')

    def formula_handler(self, arguments: List, curr_cell: Cell):
        if len(arguments) == 1:
            return self.evaluate_parse_tree(curr_cell, arguments[0])

        src_tree, dst_tree = (arguments[0], arguments[1])

        formula_value = self.evaluate_parse_tree(curr_cell, src_tree)
        formula_value = AbstractDataType.unwrap_operand(self, formula_value)

        dst_cell = self.evaluate_parse_tree(curr_cell, dst_tree)

        # cast the destination cell if necessary
        if isinstance(dst_cell, Cell):
            pass
        elif isinstance(dst_cell, Range):
            pass
        elif isinstance(dst_cell, str):
            sheet, col, row = Cell.parse_cell_addr(dst_cell)
            sheet = sheet or curr_cell.sheet.name
            dst_cell = self.memory[sheet][(col, row)]
        else:
            raise RuntimeError(f'Invalid destination cell {dst_cell}')

        # add the condition to the current branch's solver
        dst_cell.formula = formula_value
        dst_cell.value = formula_value
        return True

    def exec_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)
        self.append_ioc('EXEC', arg)
        return True

    def files_handler(self, arguments: List, curr_cell: Cell):
        ## XXXXX
        return 1

    def fpos_handler(self, arguments: List, curr_cell: Cell):
        return True

    def fread_handler(self, arguments: List, curr_cell: Cell):
        return Solver.get_abstract_var(z3.String, prefix='fread_handler')

    def radians_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        if AbstractDataType.is_abstract(arg):
            var = Solver.get_abstract_var(z3.Real, prefix='radians_handler')
            self.solver.add(var >= 0)
            self.solver.add(var <= math.pi*2)
            return var
        try:
            return math.radians(arg)
        except ValueError:
            return '#NUM!'

    def register_handler(self, arguments: List, curr_cell: Cell):
        module_text   = self.evaluate_parse_tree(curr_cell, arguments[0])
        procedure     = self.evaluate_parse_tree(curr_cell, arguments[1])
        type_text     = self.evaluate_parse_tree(curr_cell, arguments[2])
        function_text = self.evaluate_parse_tree(curr_cell, arguments[3])
        macro_type    = self.evaluate_parse_tree(curr_cell, arguments[4]) or 1
        category      = self.evaluate_parse_tree(curr_cell, arguments[5]) or 1
        shortcut      = self.evaluate_parse_tree(curr_cell, arguments[6])
        module_text, procedure, function_text = AbstractDataType.unwrap_operands(self, module_text, procedure, function_text)
        self.register[function_text] = (module_text, procedure, type_text)
        ## XXX REGISTER seems to return a pointer to the function!
        return Solver.get_abstract_var(z3.Int, prefix='register_handler')

    def fopen_handler(self, arguments: List, curr_cell: Cell):
        filename = self.evaluate_parse_tree(curr_cell, arguments[0])
        filename = AbstractDataType.unwrap_operand(self, filename)
        fd = self.fs.fopen(filename, "")
        self.append_ioc('FOPEN', [filename, fd])
        return fd
        # return Solver.get_abstract_var(z3.Int, prefix='fopen_handler')

    def fsize_handler(self, arguments: List, curr_cell: Cell):
        f = self.evaluate_parse_tree(curr_cell, arguments[0])
        f = AbstractDataType.unwrap_operand(self, f)
        return self.fs.fsize(f)

        # return Solver.get_abstract_var(z3.Int, prefix='fsize_handler')

    def fclose_handler(self, arguments: List, curr_cell: Cell):
        return True

    def fwriteln_handler(self, arguments: List, curr_cell: Cell):
        fd       = self.evaluate_parse_tree(curr_cell, arguments[0])
        content  = self.evaluate_parse_tree(curr_cell, arguments[1])
        fd, content = AbstractDataType.unwrap_operands(self, fd, content)
        self.append_ioc('FWRITELN', [fd, content])
        self.fs.fwrite(fd, content )

        return True

    def fwrite_handler(self, arguments: List, curr_cell: Cell):
        fd       = self.evaluate_parse_tree(curr_cell, arguments[0])
        content  = self.evaluate_parse_tree(curr_cell, arguments[1])
        fd, content = AbstractDataType.unwrap_operands(self, fd, content)
        self.append_ioc('FWRITE', [fd, content])
        self.fs.fwrite(fd, content)
        return True

    def indirect_handler(self, arguments: List, curr_cell: Cell):
        assert len(arguments) == 1
        target = self.evaluate_parse_tree(curr_cell, arguments[0])

        target_sheet, target_col, target_row = Cell.parse_cell_addr(target)
        if target_sheet is None:
            target_sheet = curr_cell.sheet.name

        return self.memory[target_sheet][(target_col, target_row)].value

    def average_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)
        return sum(parsed_arguments) / len(parsed_arguments)

    def address_handler(self, arguments: List, curr_cell: Cell):
        row = self.evaluate_parse_tree(curr_cell, arguments[0])
        row = AbstractDataType.unwrap_operand(self, row)

        col = Cell.convert_to_column_name(int(self.evaluate_parse_tree(curr_cell, arguments[1])))

        if len(arguments) == 5:
            sheet = self.evaluate_parse_tree(curr_cell, arguments[4])
            return '%s!$%s$%d' % (sheet, col, int(row))

        return '$%s$%d' % (col, int(row))

    def halt_handler(self, arguments: List, curr_cell: Cell):
        # stop the control flow for the current branch
        self.halt = True
        return True

    def concatenate_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        text_left = parsed_arguments[0]
        for right_arg_value in parsed_arguments[1:]:
            text_left = AbstractDataType.process_concrete_operation(text_left, right_arg_value, AbstractDataType.OPERATORS['+'])

        return text_left

    def asin_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        if AbstractDataType.is_abstract(arg):
            var = Solver.get_abstract_var(z3.Real, prefix='asin_handler')
            self.solver.add(var >= math.pi/2)
            self.solver.add(var <= math.pi)
            return var
        try:
            return math.acos(arg)
        except ValueError:
            return '#NUM!'

    def acos_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        if AbstractDataType.is_abstract(arg):
            var = Solver.get_abstract_var(z3.Real, prefix='acos_handler')
            self.solver.add(var >=  0)
            self.solver.add(var <=  math.pi)
            return var

        try:
            return math.acos(arg)
        except ValueError:
            return '#NUM!'

    def cos_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        if AbstractDataType.is_abstract(arg):
            var = Solver.get_abstract_var(z3.Real, prefix='cos_handler')
            self.solver.add(var >= -1)
            self.solver.add(var <=  1)
            return var
        return math.cos(arg)

    def code_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)

        # abstract case
        if AbstractDataType.is_abstract(arg):
            assert isinstance(arg, AbstractChar)
            return arg.ascii_value

        # concrete case
        value = ord(arg)
        if value > 256:
            # encode as Windows-1252
            value = ord(arg.encode('cp1252'))
        return value

    def mod_handler(self, arguments: List, curr_cell: Cell):
        a = self.evaluate_parse_tree(curr_cell, arguments[0])
        b = self.evaluate_parse_tree(curr_cell, arguments[1])
        a, b = AbstractDataType.unwrap_operands(self, a, b)

        if AbstractDataType.is_abstract(a) or AbstractDataType.is_abstract(b):
            return AbstractDataType.cast_to_int(a) % AbstractDataType.cast_to_int(b)
        else:
            return a % b

    def sin_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        if AbstractDataType.is_abstract(arg):
            var = Solver.get_abstract_var(z3.Real, prefix='sin_handler')
            self.solver.add(var >= -1)
            self.solver.add(var <=  1)
            return var
        return math.sin(arg)

    def trunc_handler(self, arguments: List, curr_cell: Cell):
        number = self.evaluate_parse_tree(curr_cell, arguments[0])
        if len(arguments) > 1:
            precision = self.evaluate_parse_tree(curr_cell, arguments[1])
        else:
            precision = 1

        x = 10 ** precision
        return math.trunc(number * x) / x

    def trim_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)
        if AbstractDataType.is_abstract(arg):
            raise TypeError('Unsupported symbolic argument in TRIM')
        elif not isinstance(arg, str):
            # e.g., True --> "TRUE", 13 --> "13"
            return str(arg).upper()
        else:
            return arg.strip()

    def lower_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)
        if isinstance(arg, int):
            return arg
        else:
            return arg.lower()

    def len_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)

        arg = AbstractDataType.cast_to_string(arg)

        if AbstractDataType.is_abstract(arg):
            return z3.Length(arg.bv_repr)

        return len(arg) if arg else 0

    def fact_handler(self, arguments: List, curr_cell: Cell):
        number   = self.evaluate_parse_tree(curr_cell, arguments[0])
        return math.prod(range(0, number))


    def get_if_endif_record(self, curr_cell):
        body_statements = [curr_cell.coordinates]
        # find corresponding elseif/else/endif statements
        counter = 0
        for c in self.curr_cell.successors:
            if AbstractDataType.is_abstract(c.formula):
                # concretize the cell
                self.concretize_cell(c)

            if c.formula is None:
                continue
            elif c.formula.startswith('=IF('):
                # we have a nested if only if the syntax has a single argument
                parse_tree = self.simgr.xlm_parser.parse(c.formula).children[0]
                arglist = parse_tree.children[2].children
                if len(arglist) == 1:
                    counter += 1
            elif c.formula.startswith('=ELSE.IF') and counter == 0:
                body_statements.append(c.coordinates)
            elif c.formula.startswith('=ELSE') and counter == 0:
                body_statements.append(c.coordinates)
            elif c.formula.startswith('=END.IF') and counter == 0:
                body_statements.append(c.coordinates)
                break
            elif c.formula.startswith('=ENDIF'):
                counter -= 1

        return {'body': body_statements,
                'processed': False}

    def _if_endif(self, arguments: List, curr_cell: Cell):
        # this sub-handler is used by both the IF and ELSEIF handlers

        current_record = self.if_stack[-1]

        # if the current record is already processed, return False and jump to the next IF/ENDIF statement
        if current_record['processed'] is True:
            current_index = current_record['body'].index(curr_cell.coordinates)
            try:
                next_sheet, next_col, next_row = current_record['body'][current_index + 1]
                self.curr_cell = self.memory[next_sheet][(next_col, next_row)]
            except IndexError:
                log.warning('Something went wrong while processing IF, stepping to next cell...')
                self.curr_cell = self.curr_cell.next()
            return False

        # eval conditions
        cond_eval_result = self.evaluate_parse_tree(curr_cell, arguments[0])
        cond_eval_result = AbstractDataType.unwrap_operand(self, cond_eval_result)
        constraint = Solver.process_constraint(cond_eval_result)

        if isinstance(constraint, bool):
            # if the constraint is concrete, we know which branch is satisfiable
            sat_true = constraint is True
            sat_false = constraint is False
        else:
            # else, check if both branches are satisfiable
            sat_true = self.solver.check_constraint_sat(constraint)
            sat_false = self.solver.check_constraint_sat(z3.Not(constraint))

        if sat_true and sat_false:
            log.debug('both branches are satisfiable')
            # create the false branch
            false_branch = self.create_new_branch([z3.Not(constraint)])
            false_branch.if_stack[-1]['processed'] = False

            # add the constraint to the current branch's solver
            self.solver.add(constraint)
            current_record['processed'] = True
            result = True
        elif sat_true:
            log.debug('only true branch is satisfiable')
            self.solver.add(constraint)

            current_record['processed'] = True
            result = True
        elif sat_false:
            log.debug('only false branch is satisfiable')
            self.solver.add(z3.Not(constraint))
            current_record['processed'] = False

            # lookup the next elseif/else/endif statement and jump there
            current_index = current_record['body'].index(curr_cell.coordinates)
            next_sheet, next_col, next_row = current_record['body'][current_index + 1]
            self.curr_cell = self.memory[next_sheet][(next_col, next_row)]
            result = False

        return result

    def if_endif_handler(self, arguments: List, curr_cell: Cell):
        # add a new record to the if stack if it's not there (e.g., after branch+re-execute with different constraints)
        if len(self.if_stack) == 0 or self.if_stack[-1]['body'][0] != curr_cell.coordinates:
            current_record = self.get_if_endif_record(curr_cell)
            self.if_stack.append(current_record)

        return self._if_endif(arguments, curr_cell)

    def elseif_handler(self, arguments: List, curr_cell: Cell):
        return self._if_endif(arguments, curr_cell)

    def else_handler(self, arguments: List, curr_cell: Cell):
        current_record = self.if_stack[-1]

        # if the current record is already processed, jump to the endif statement
        if current_record['processed'] is True:
            next_sheet, next_col, next_row = current_record['body'][-1]
            self.curr_cell = self.memory[next_sheet][(next_col, next_row)]
            return False

        # else, set the current if record as processed and continue
        current_record['processed'] = True
        return True

    def endif_handler(self, arguments: List, curr_cell: Cell):
        # pop the entry at the top of the if stack and continue
        self.if_stack.pop()

        return True

    def if_handler(self, arguments: List, curr_cell: Cell):
        if len(arguments) == 1:
            # handle if/elseif/else/endif statement
            self.handlers_log[-1] += '_[if_endif]'
            return self.if_endif_handler(arguments, curr_cell)
        if len(arguments) == 2:
            arguments += [None]
        # elif len(arguments) != 3:
        #     raise NotImplementedError("This IF syntax is not implemented")

        result = False
        # -- EVAL ARG 0
        cond_eval_result = self.evaluate_parse_tree(curr_cell, arguments[0])

        cond_eval_result = AbstractDataType.unwrap_operand(self, cond_eval_result)

        if isinstance(cond_eval_result, bool):
            # if the condition is a bool variable, only one branch is possible
            if cond_eval_result is True:
                log.debug('only true branch possible (bool)')
                result = self.evaluate_parse_tree(curr_cell, arguments[1])
            else:
                log.debug('only false branch possible (bool)')
                result = self.evaluate_parse_tree(curr_cell, arguments[2])
        else:
            # else, check if both branches are satisfiable
            constraint = Solver.process_constraint(cond_eval_result)
            sat_true = self.solver.check_constraint_sat(constraint)
            sat_false = self.solver.check_constraint_sat(z3.Not(constraint))

            if sat_true and sat_false:
                log.debug('both branches are satisfiable')
                # both branches are satisfiable
                # -- EVAL ARG 1
                # create the true branch
                new_branch = self.create_new_branch([z3.Not(constraint)])

                # -- EVAL ARG 2
                # add the constraint to the current branch's solver
                self.solver.add(constraint)
                # execute the false branch
                result = self.evaluate_parse_tree(curr_cell, arguments[1])
            elif sat_true:
                log.debug('only true branch is satisfiable')
                # -- EVAL ARG 1 (only true branch is satisfiable)
                self.solver.add(constraint)
                result = self.evaluate_parse_tree(curr_cell, arguments[1])
            elif sat_false:
                log.debug('only false branch is satisfiable')
                # -- EVAL ARG 2 (only false branch is satisfiable)
                self.solver.add(z3.Not(constraint))
                result = self.evaluate_parse_tree(curr_cell, arguments[2])

        return result

    def int_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = AbstractDataType.unwrap_operand(self, value)

        return AbstractDataType.cast_to_int(value)

    def iserror_handler(self, arguments: List, curr_cell: Cell):
        arg = self.evaluate_parse_tree(curr_cell, arguments[0])
        arg = AbstractDataType.unwrap_operand(self, arg)

        success = Solver.process_constraint(arg)
        if isinstance(success, bool):
            return not success
        else:
            return z3.Not(success)

    def isnumber_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])

        if isinstance(value, int):
            return True
        elif isinstance(value, z3.ArithRef) and value.decl().name() == 'str.indexof':
            return self.solver.get_observer((value >= 0), prefix='observer_isnumber', z3_type=z3.Bool)
        elif isinstance(value, z3.ArithRef):
            return True
        else:
            return False

    def next_handler(self, arguments: List, curr_cell: Cell):
        # read the location of the WHILE statement from the while stack (this can fail, and it's fine)
        while_sheet, while_col, while_row = self.while_stack[self.curr_cell.coordinates]
        # jump to the WHILE statement
        self.curr_cell = self.memory[while_sheet][(while_col, while_row)]

        return True

    def rand_handler(self, arguments: List, curr_cell: Cell):
        return 42

    def reset_toolbar_handler(self, arguments: List, curr_cell: Cell):
        return True

    def pause_handler(self, arguments: List, curr_cell: Cell):
        return True

    def pi_handler(self, arguments: List, curr_cell: Cell):
        return math.pi

    def save_handler(self, arguments: List, curr_cell: Cell):
        return True

    def save_copy_as_handler(self, arguments: List, curr_cell: Cell):
        fname = self.evaluate_parse_tree(curr_cell, arguments[0])
        fname = AbstractDataType.unwrap_operand(curr_cell, fname)
        print(fname)
        return True

    def sumxmy2_handler(self, arguments: List, curr_cell: Cell):
        array_x = self.evaluate_parse_tree(curr_cell, arguments[0])
        array_y = self.evaluate_parse_tree(curr_cell, arguments[0])

        assert(isinstance(array_x, int))
        assert(isinstance(array_y, int))

        return (array_x - array_y) ** 2

    def sumproduct_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = list(AbstractDataType.unwrap_operands(self, *parsed_arguments))

        total = 1
        for arg in parsed_arguments:
            if isinstance(arg, Range):
                partial = sum([e.value or 0 for e in arg.get_all_cells()])
            elif arg is None:
                partial = 0
            else:
                partial = arg
                #raise TypeError(f"Unsupported type {type(arg)} in sumproduct handler")
                
            total *= partial

        return total


    def sum_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        return sum(parsed_arguments)

    def t_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = AbstractDataType.unwrap_operand(self, value)

        if isinstance(value, (str, AbstractString, z3.SeqRef, AbstractChar)):
            result = value
        elif isinstance(value, Range):
            result = ''.join(value.value)
        elif isinstance(value, Cell):
            result = value.value
        else:
            result = ""

        return result

    def text_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        format_string = self.evaluate_parse_tree(curr_cell, arguments[1])

        log.warning('evaluating TEXT formula but ignoring the format string')

        return AbstractDataType.cast_to_string(value)

    def value_handler(self, arguments: List, curr_cell: Cell):
        text = self.evaluate_parse_tree(curr_cell, arguments[0])
        text = AbstractDataType.unwrap_operand(self, text)

        return AbstractDataType.cast_to_real(text)

    def while_handler(self, arguments: List, curr_cell: Cell):
        # add a new record to the while stack if it's not there
        if curr_cell.coordinates not in self.while_stack:
            # find corresponding next statement
            counter = 0
            for c in self.curr_cell.successors:
                if AbstractDataType.is_abstract(c.formula):
                    # concretize the cell
                    self.concretize_cell(c)

                # log.debug(curr_cell, 'scanning successor', c, c.formula)
                if c.formula is None:
                    continue
                elif c.formula.startswith('=WHILE('):
                    counter += 1
                elif c.formula.startswith('=NEXT()'):
                    if counter == 0:
                        # found the matching NEXT statement, add two new records (WHILE and NEXT)
                        # log.debug('found matching next', c)
                        self.while_stack[curr_cell.coordinates] = c.coordinates
                        self.while_stack[c.coordinates] = curr_cell.coordinates
                        break
                    else:
                        counter -= 1

        condition = self.evaluate_parse_tree(curr_cell, arguments[0])

        if AbstractDataType.is_abstract(condition):
            raise TypeError("Unsupported symbolic condition in while handler")

        if not condition:
            # read the location of the NEXT statement from the while stack (this can fail, and it's fine)
            next_sheet, next_col, next_row = self.while_stack[self.curr_cell.coordinates]
            # pop the WHILE/NEXT records from the while stack
            del self.while_stack[self.curr_cell.coordinates]
            del self.while_stack[(next_sheet, next_col, next_row)]
            # jump after the NEXT statement (this will update self.curr_cell!)
            self.curr_cell = self.memory[next_sheet][(next_col, next_row+1)]

        return True

    def goto_handler(self, arguments: List, curr_cell: Cell):
        self.curr_cell = self.evaluate_parse_tree(curr_cell, arguments[0])

    def hlookup_handler(self, arguments: List, curr_cell: Cell):
        lookup_value = self.evaluate_parse_tree(curr_cell, arguments[0])
        table_array = self.evaluate_parse_tree(curr_cell, arguments[1])
        row_index_num = int(self.evaluate_parse_tree(curr_cell, arguments[2]))
        partial_match = self.evaluate_parse_tree(curr_cell, arguments[3])

        assert isinstance(table_array, Range)

        if partial_match is True:
            raise NotImplementedError('HLOOKUP with partial match not implemented')


        if lookup_value == '*':  # table_array.scol == table_array.ecol and
            # this is the simple case, just return the requested row
            return self.memory[table_array.sheet.name][(table_array.scol, table_array.srow + row_index_num - 1)].value

        # else, we need to find a matching column
        header = table_array.get_all_cells(row=table_array.srow)

        if any([AbstractDataType.is_abstract(c.value) for c in header]):
            raise TypeError("Unsupported abstract operands in HLOOKUP")

        regex = re.compile(lookup_value.replace('*', '.*').replace('?', '.?'))
        for cell in header:
            if regex.fullmatch(cell.value):
                return self.memory[cell.sheet.name][(cell.column, table_array.srow+row_index_num-1)].value

        return "#N/A"

    def index_handler(self, arguments: List, curr_cell: Cell):
        array = self.evaluate_parse_tree(curr_cell, arguments[0])
        array = AbstractDataType.unwrap_operand(self, array)

        row = self.evaluate_parse_tree(curr_cell, arguments[1])
        row = AbstractDataType.unwrap_operand(self, row)
        row = int(row)
        if len(arguments) > 2:
            return NotImplementedError('Column argument not implemented in INDEX')
        elif row == 0:
            return NotImplementedError('Row=0 not implemented in INDEX')

        if isinstance(array, Range):
            return array.get_all_cells(row=(row-1))[0].value
        elif isinstance(array, list):
            return array[row-1]

    def message_handler(self, arguments: List, curr_cell: Cell):
        return

    def max_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        if any([AbstractDataType.is_abstract(a) for a in parsed_arguments]):
            raise TypeError("Unsupported abstract operands in MAX")

        return max(parsed_arguments)

    def min_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        if any([AbstractDataType.is_abstract(a) for a in parsed_arguments]):
            raise TypeError("Unsupported abstract operands in MIN")

        return min(parsed_arguments)

    def mid_handler(self, arguments: List, curr_cell: Cell):
        str_arg_value = self.evaluate_parse_tree(curr_cell, arguments[0])
        base_arg_value = self.evaluate_parse_tree(curr_cell, arguments[1])
        len_arg_value = self.evaluate_parse_tree(curr_cell, arguments[2])

        # if any operand is abstract, do the abstract operation
        str_arg_value, base_arg_value, len_arg_value = AbstractDataType.unwrap_operands(self, str_arg_value, base_arg_value,
                                                                                        len_arg_value)

        if AbstractDataType.is_abstract(str_arg_value) or AbstractDataType.is_abstract(
                base_arg_value) or AbstractDataType.is_abstract(len_arg_value):
            if isinstance(str_arg_value, (AbstractString, AbstractChar)):
                str_arg_value = str_arg_value.bv_repr
            return z3.SubString(str_arg_value, base_arg_value, len_arg_value)
        # otherwise, do the concrete operation
        else:
            return str_arg_value[
                   int(float(base_arg_value)) - 1:int(float(base_arg_value)) + int(float(len_arg_value)) - 1]

    def not_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = AbstractDataType.unwrap_operand(self, value)
        value = Solver.process_constraint(value)

        if AbstractDataType.is_abstract(value):
            return z3.Not(value)
        else:
            return not value

    def now_handler(self, arguments: List, curr_cell: Cell):
        self.init_datetime()
        return self.environment['datetime.now']

    def wait_handler(self, arguments: List, curr_cell: Cell):
        self.init_datetime()

        new_time = self.evaluate_parse_tree(curr_cell, arguments[0])
        self.environment['datetime.now'] = new_time

        return True

    def offset_handler(self, arguments: List, curr_cell: Cell):
        # =OFFSET (reference, rows, cols, [height], [width])

        reference = self.evaluate_parse_tree(curr_cell, arguments[0])
        rows = self.evaluate_parse_tree(curr_cell, arguments[1])
        cols = self.evaluate_parse_tree(curr_cell, arguments[2])

        assert isinstance(reference, (Cell, Range))
        if isinstance(reference, Range):
            reference = reference.get_all_cells()[0]

        if len(arguments) == 3:
            height = 1
            width = 1
        elif len(arguments) == 5:
            height = self.evaluate_parse_tree(curr_cell, arguments[3])
            width = self.evaluate_parse_tree(curr_cell, arguments[4])
        else:
            raise NotImplementedError('Invalid number of arguments for OFFSET')

        rows, cols, height, width = AbstractDataType.unwrap_operands(self, rows, cols, height, width)

        if any([AbstractDataType.is_abstract(a) for a in [rows, cols, height, width]]):
            raise TypeError("Unsupported abstract operands in OFFSET")

        start_row = int(reference.row + rows)
        start_col = int(Cell.convert_to_column_index(reference.column) + cols)

        end_row = int(start_row + height - 1)
        end_col = int(start_col + width - 1)

        # convert column indices to names
        start_col = Cell.convert_to_column_name(start_col)
        end_col = Cell.convert_to_column_name(end_col)

        result = Range(reference.sheet, start_row, end_row, start_col, end_col)

        return result

    def on_time_handler(self, arguments: List, curr_cell: Cell):

        # time = self.evaluate_parse_tree(curr_cell, arguments[0])
        next_sheet, next_col, next_row = self.get_cell_addr(curr_cell, arguments[1])
        entry_point = self.memory[next_sheet][(next_col, next_row)]

        # start a new subroutine
        self.enter_subroutine(entry_point)

    def or_handler(self, arguments: List, curr_cell: Cell):
        parsed_arguments = [self.evaluate_parse_tree(curr_cell, a) for a in arguments]
        parsed_arguments = AbstractDataType.unwrap_operands(self, *parsed_arguments)

        if any([AbstractDataType.is_abstract(a) for a in parsed_arguments]):
            observed_value = z3.Or([Solver.process_constraint(c) for c in parsed_arguments])
            return self.solver.get_observer(observed_value, prefix='observer_or', z3_type=z3.Bool)

        return any([Solver.process_constraint(c) for c in parsed_arguments])

    def proper_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])

        # make the first letter uppercase
        if AbstractDataType.is_abstract(value):
            raise TypeError("Unsupported abstract operand in PROPER")

        return value[:1].capitalize() + value[1:]

    def randbetween_handler(self, arguments: List, curr_cell: Cell):
        min = self.evaluate_parse_tree(curr_cell, arguments[0])
        max = self.evaluate_parse_tree(curr_cell, arguments[1])

        # rand = Solver.get_abstract_var(z3.Int, prefix='randbetween_handler')
        # self.solver.add(rand >= min)
        # self.solver.add(rand <= max)
        # return rand

        return min

    def replace_handler(self, arguments: List, curr_cell: Cell):
        old_text = self.evaluate_parse_tree(curr_cell, arguments[0])
        start_num = self.evaluate_parse_tree(curr_cell, arguments[1])
        num_chars = self.evaluate_parse_tree(curr_cell, arguments[2])
        new_text = self.evaluate_parse_tree(curr_cell, arguments[3])

        old_text, start_num, num_chars, new_text = AbstractDataType.unwrap_operands(self, old_text, start_num, num_chars, new_text)

        # make the first letter uppercase
        if any([AbstractDataType.is_abstract(a) for a in [old_text, start_num, num_chars, new_text]]):
            raise TypeError("Unsupported abstract operands in REPLACE")

        start_num = int(start_num)
        num_chars = int(num_chars)
        return old_text[:start_num-1] + new_text[:num_chars] + old_text[start_num+num_chars-1:]

    def return_handler(self, arguments: List, curr_cell: Cell):
        _ = self.evaluate_parse_tree(curr_cell, arguments[0])

        # pop the parent routine address from the subroutine stack
        if len(self.subroutine_stack) > 0:
            sheet, col, row = self.subroutine_stack.pop()
            saved_return_cell = self.memory[sheet][(col, row)]

            # return from the current subroutine
            self.curr_cell = saved_return_cell
        else:
            log.warning('Calling RETURN with an empty call stack. Something could be wrong')
            self.halt = True
            return True

    def rows_handler(self, arguments: List, curr_cell: Cell):
        assert len(arguments) == 1
        parsed_argument = self.evaluate_parse_tree(curr_cell, arguments[0])
        (parsed_argument,) = AbstractDataType.unwrap_operands(self, parsed_argument)

        if isinstance(parsed_argument, AbstractString) and arguments[0].type == 'NAME':
            self.concretize_defined_name(arguments[0].value)
            # re-evaluate the argument has been concretized
            parsed_argument = self.evaluate_parse_tree(curr_cell, arguments[0])
            (parsed_argument,) = AbstractDataType.unwrap_operands(self, parsed_argument)
        elif isinstance(parsed_argument, AbstractString):
            raise NotImplementedError

        # count the number of numerical values
        if isinstance(parsed_argument, Range):
            return parsed_argument.erow - parsed_argument.srow + 1
        elif isinstance(parsed_argument, list):
            return len(parsed_argument)
        else:
            return 1

    def roundup_handler(self, arguments: List, curr_cell: Cell):
        value = self.evaluate_parse_tree(curr_cell, arguments[0])
        precision = self.evaluate_parse_tree(curr_cell, arguments[1])

        value, precision = AbstractDataType.unwrap_operands(self, value, precision)

        if AbstractDataType.is_abstract(precision):
            raise TypeError("Unsupported abstract precision in ROUNDUP")

        if AbstractDataType.is_abstract(value):
            # if precision == 0 create a new Int variable
            if precision == 0:
                result = self.solver.get_abstract_var(z3.Int, prefix='roundup')
                # constrain it to be value < (int)result < value+1
                self.solver.add(result > value)
                self.solver.add(result < value + 1)
            # else use the same trick that we use for concrete values, but we need an int "helper"
            else:
                helper = self.solver.get_abstract_var(z3.Int, prefix='roundup_helper')

                self.solver.add(helper >= value * (10 ** precision))
                self.solver.add(helper < value * (10 ** precision) + 1)
                result = AbstractDataType.process_operation(self.solver, helper, 10 ** precision, AbstractDataType.OPERATORS['/'])
        else:
            result = math.ceil(value * (10 ** precision)) / (10 ** precision)

        return result

    def right_handler(self, arguments: List, curr_cell: Cell):
        string = str(self.evaluate_parse_tree(curr_cell, arguments[0]))
        length = self.evaluate_parse_tree(curr_cell, arguments[1])
        return string[-length:]

    def left_handler(self, arguments: List, curr_cell: Cell):
        string = str(self.evaluate_parse_tree(curr_cell, arguments[0]))
        length = self.evaluate_parse_tree(curr_cell, arguments[1])
        return string[:length]

    def run_handler(self, arguments: List, curr_cell: Cell):
        next_sheet, next_col, next_row = self.get_cell_addr(curr_cell, arguments[0])
        entry_point = self.memory[next_sheet][(next_col, next_row)]

        # create a new subroutine
        self.enter_subroutine(entry_point)

    def search_handler(self, arguments: List, curr_cell: Cell):
        search = self.evaluate_parse_tree(curr_cell, arguments[0])
        text = self.evaluate_parse_tree(curr_cell, arguments[1])

        search, text = AbstractDataType.unwrap_operands(self, search, text)

        if isinstance(search, (AbstractString, AbstractChar)):
            search = search.bv_repr
        if isinstance(text, (AbstractString, AbstractChar)):
            text = text.bv_repr

        # abstract case
        if AbstractDataType.is_abstract(search) or AbstractDataType.is_abstract(text):
            indexof = z3.IndexOf(text, search, 0)
        # concrete case
        else:
            if search in text:
                indexof = text.find(search)
            else:
                indexof = 'NA'

        return indexof

    def set_name_handler(self, arguments: List, curr_cell: Cell):
        assert len(arguments) == 2

        name  = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = self.evaluate_parse_tree(curr_cell, arguments[1])
        if isinstance(value, str):
            value = value.replace('"', '""')
            value = f'="{value}"'
        self.defined_names[name.lower()] = value

        # log.debug(f'SET.NAME({name.lower()}, {value})')

        return True

    def set_value_handler(self, arguments: List, curr_cell: Cell):
        cell = self.evaluate_parse_tree(curr_cell, arguments[0])
        value = self.evaluate_parse_tree(curr_cell, arguments[1])
        value = AbstractDataType.unwrap_operand(self, value)
        cell.value = value

        # if AbstractDataType.is_abstract(value):
        #     _, value = list(self.solver.eval_one_expression(value).items())[0]

        # log.debug(f'SETTING VALUE {value}')
        return True

    def workbook_hide_handler(self, arguments: List, curr_cell: Cell):
        return True

    def workbook_unhide_handler(self, arguments: List, curr_cell: Cell):
        return True
