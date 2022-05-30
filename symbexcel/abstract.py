import datetime
import logging
import operator
from typing import Union

import z3

from .boundsheet import Cell

log = logging.getLogger(__name__)


dummy_solver = z3.Solver()


def serialize_expression(expression):
    # trick to serialize z3 expressions
    s = z3.Solver()
    s.add(expression == expression)
    return s.sexpr()


def deserialize_expression(self, s_expression):
    global dummy_solver
    dummy_solver.from_string(s_expression)
    new_object = dummy_solver.assertions()[-1].children()[0]
    self.__dict__ = dict(new_object.__dict__)


def del_ast(self):
    return
    # if self.ctx.ref() is not None and self.ast is not None:
    #     z3.Z3_dec_ref(self.ctx.ref(), self.as_ast())
    #     self.ast = None


# override z3 __getstate__ and __setstate__
z3.ExprRef.__getstate__ = serialize_expression
z3.ExprRef.__setstate__ = deserialize_expression

# override z3 AstRef.__del__
z3.AstRef.__del__ = del_ast


class Solver:
    z3_names = dict()

    def __init__(self, solver=None, observers=None):
        self._solver = solver or z3.Solver()
        self._solver.set("timeout", 15*1000)
        self.observers = observers or dict()

    def __deepcopy__(self):
        new_solver = self._solver.translate(self._solver.ctx)
        return Solver(solver=new_solver, observers=dict(self.observers))

    def __getstate__(self):
        state = {
            '_solver': self._solver.sexpr(),
            'observers': self.observers,
            'z3_names': Solver.z3_names
        }
        return state

    def __setstate__(self, state):
        self._solver = z3.Solver()
        self._solver.add(z3.parse_smt2_string(state['_solver']))
        self.observers = state['observers']
        Solver.z3_names = state['z3_names']

    @staticmethod
    def process_constraint(raw_constraint):
        if AbstractDataType.is_concrete(raw_constraint):
            constraint = bool(raw_constraint)
        elif isinstance(raw_constraint, z3.BoolRef):
            constraint = raw_constraint
        elif isinstance(raw_constraint, z3.ArithRef):
            constraint = (raw_constraint != 0)
        else:
            log.error(f'Unsopported condition type: {raw_constraint}')
            raise TypeError

        return constraint

    def add(self, raw_constraint: Union[bool, z3.ArithRef, z3.BoolRef], silent=False):
        constraint = Solver.process_constraint(raw_constraint)

        # ignore concrete values
        if AbstractDataType.is_concrete(constraint):
            return

        constraint = z3.simplify(constraint)

        # check again after the simplification if the constraint is concrete (e.g., simplified to z3.true or z3.false)
        if AbstractDataType.is_concrete(constraint):
            return

        if not silent:
            log.debug(f'Adding constraint {constraint} to solver')
        self._solver.add(constraint)

    @staticmethod
    def get_abstract_var(z3_type: type, prefix: str = 'tmp') -> Union[z3.BitVecRef, z3.ArithRef, z3.SeqRef, z3.BoolRef]:
        Solver.z3_names[prefix] = Solver.z3_names.get(prefix, 0) + 1

        if z3_type == z3.BitVec:
            var = z3_type(f'{prefix}_{Solver.z3_names[prefix]}', 8)
        else:
            var = z3_type(f'{prefix}_{Solver.z3_names[prefix]}')

        return var

    def get_observer(self, value, prefix='observer', z3_type=z3.Bool):
        if value not in self.observers:
            observer = Solver.get_abstract_var(z3_type, prefix)
            self.add(observer == value)
            self.observers[value] = observer

        return self.observers[value]

    def check_constraint_sat(self, constraint: z3.BoolRef) -> bool:
        if not self._solver.check() == z3.sat:
            log.error('Solver is already unsat -- no need to check with a new constraint')
            return False

        # backup the solver
        self._solver.push()

        # add the constraint
        self._solver.add(constraint)

        # check if sat
        res = (self._solver.check() == z3.sat)

        # restore the solver
        self._solver.pop()

        return res

    @staticmethod
    def get_ast_terminals(expression):
        if AbstractDataType.is_concrete(expression):
            return []
        elif isinstance(expression, z3.SeqRef) and expression.is_string_value():
            return []
        elif isinstance(expression, (z3.IntNumRef, z3.RatNumRef)):
            return []
        elif expression.num_args() == 0:
            return [expression]
        else:
            terminals = []
            for children in expression.children():
                terminals += Solver.get_ast_terminals(children)
            return list(set(terminals))

    def get_all_models(self, terminals, n_max=256):
        if len(terminals) == 0:
            assert self._solver.check() == z3.sat
            return [self._solver.model()]

        t = terminals[0]

        # get all the solutions for the current terminal
        solutions = self.eval_n_terminal(t, n_max)

        # for every solution: backup the solver, fix the solution, recurse, restore the solver
        models = []
        for solution in solutions:
            # log.debug(f'processing solution {solution} for terminal {t}')
            self._solver.push()
            self._solver.add(t == solution)
            models += self.get_all_models(terminals[1:], n_max)
            self._solver.pop()

        return models

    def get_all_constraints(self, expression, model):
        if isinstance(expression, (AbstractString, AbstractChar)):
            expression = expression.bv_repr

        terminals = self.get_ast_terminals(expression)
        return [t == model[t] for t in terminals]

    def eval_n_terminal(self, t, n):
        self._solver.push()
        solutions = []
        for _ in range(n):
            if self._solver.check() == z3.unsat:
                break
            model = self._solver.model()
            sol = model.eval(t, model_completion=True)
            solutions += [sol]

            # enforce distinct solutions
            self._solver.add(t != sol)
        self._solver.pop()

        return solutions

    def eval_all_expression(self, expression, verifier=lambda expression: None, n_max=256):
        if isinstance(expression, (AbstractString, AbstractChar)):
            expression = expression.bv_repr

        terminals = Solver.get_ast_terminals(expression)
        models = self.get_all_models(terminals, n_max)
        solutions = {model: model.eval(expression, model_completion=True).as_string() for model in models}

        for model, solution in dict(solutions).items():
            try:
                verifier(solution)
            except:
                del solutions[model]

        return solutions

    def eval_one_expression(self, expression, verifier=lambda expression: None):
        solutions = self.eval_all_expression(expression, verifier, n_max=1)
        return dict([list(solutions.items())[0], ])

    def get_one_model(self):
        terminals = []

        for expression in self._solver.assertions():
            terminals += Solver.get_ast_terminals(expression)

        return self.get_all_models(terminals, 1)[0]


class AbstractDataType:
    OPERATORS = {
        '+': operator.add,
        '-': operator.sub,
        '*': operator.mul,
        '/': operator.truediv,
        '&': operator.add,
        '>': operator.gt,
        '<': operator.lt,
        '=': operator.eq,
        '<>': operator.ne,
        '>=': operator.ge,
        '<=': operator.le,
    }

    COMPARISON_OPERATORS = [operator.gt, operator.lt, operator.eq, operator.ne, operator.ge, operator.le]

    @staticmethod
    def is_abstract(value) -> bool:
        if isinstance(value, Cell):
            log.error('Error: Cell value was not unwrapped')
            raise TypeError
        # elif z3.is_true(value) or z3.is_false(value):
        #     return False
        elif isinstance(value, (z3.ExprRef, AbstractDatetime, AbstractChar, AbstractString)):
            return True
        else:
            return False

    @staticmethod
    def is_concrete(value) -> bool:
        return not AbstractDataType.is_abstract(value)

    @staticmethod
    def cast_to_int(value):
        if AbstractDataType.is_concrete(value):
            if value is None or value == '':
                result = 0
            elif isinstance(value, str):
                result = int(value.strip("'"))
            else:
                result = int(value)
        elif isinstance(value, z3.BoolRef):
            result = z3.If(value, 1, 0)
        elif isinstance(value, z3.ArithRef) and value.is_real():
            result = z3.ToInt(value)
        elif isinstance(value, z3.ArithRef) and value.is_int():
            result = value
        elif isinstance(value, z3.SeqRef):
            # log.warning("z3.StrToInt will not work for non-numerical strings (e.g., \"'42\")")
            if value.decl().name() == 'str.from_int':
                result = value.children()[0]
            else:
                result = z3.StrToInt(value)
        elif isinstance(value, AbstractString):
            # log.warning("z3.StrToInt will not work for non-numerical strings (e.g., \"'42\")")
            try:
                value.chars.remove("'")
            except:
                pass

            value = value.bv_repr
            if value.decl().name() == 'str.from_int':
                result = value.children()[0]
            else:
                result = z3.StrToInt(value)
        else:
            raise TypeError(f"Unsopported type {type(value)} in AbstractDataType.cast_to_real")

        return result

    @staticmethod
    def cast_to_real(value):
        if AbstractDataType.is_concrete(value):
            if value is None or value == '':
                result = 0.0
            elif isinstance(value, str):
                result = float(value.strip("'"))
            else:
                result = float(value)
        elif isinstance(value, z3.BoolRef):
            result = z3.If(value, 1.0, 0.0)
        elif isinstance(value, z3.ArithRef) and value.is_int():
            result = z3.ToReal(value)
        elif isinstance(value, z3.ArithRef) and value.is_real():
            result = value
        elif isinstance(value, z3.SeqRef):
            log.warning("Casting to z3.Int instead of z3.Real")
            # log.warning("z3.StrToInt will not work for non-numerical strings (e.g., \"'42\")")
            result = z3.StrToInt(value)
        elif isinstance(value, AbstractString):
            log.warning("Casting to z3.Int instead of z3.Real")
            # log.warning("z3.StrToInt will not work for non-numerical strings (e.g., \"'42\")")
            try:
                value.chars.remove("'")
            except:
                pass
            result = z3.StrToInt(value.bv_repr)
        else:
            raise TypeError(f"Unsopported type {type(value)} in AbstractDataType.cast_to_real")

        return result

    @staticmethod
    def cast_to_string(value):
        if AbstractDataType.is_concrete(value):
            if value is None:
                result = ''
            elif isinstance(value, bool):
                result = 'TRUE' if value else 'FALSE'
            else:
                result = str(value)
        else:
            result = AbstractString.cast_to_abstract_string(value)

        return result

    @staticmethod
    def unwrap_operand(state, operand):
        if not isinstance(operand, Cell):
            return operand

        if operand.sheet.type == 'Worksheet' and operand.formula is not None:
            if AbstractDataType.is_abstract(operand.formula):
                raise TypeError('Unsupported abstract formula in worksheet cell')

            # recalculate the cell value
            if operand.formula.startswith('='):
                parse_tree = state.simgr.xlm_parser.parse(operand.formula)
                operand.value = state.evaluate_parse_tree(operand, parse_tree)

        return operand.value

    @staticmethod
    def unwrap_operands(state, *operands):
        unwrapped = []
        for o in operands:
            unwrapped += [AbstractDataType.unwrap_operand(state, o)]

        return unwrapped

    @staticmethod
    def process_operation(solver, a, b, op):
        if AbstractDataType.is_abstract(a) or AbstractDataType.is_abstract(b):
            return AbstractDataType.process_abstract_operation(solver, a, b, op)
        else:
            return AbstractDataType.process_concrete_operation(a, b, op)

    @staticmethod
    def process_abstract_operation(solver, a, b, op):
        if b is None:
            return a

        # match types for AbstractDatetime, z3.BoolRef, and z3.SeqRef
        if isinstance(a, (AbstractDatetime, AbstractChar, AbstractString)) or \
                isinstance(b, (AbstractDatetime, AbstractChar, AbstractString)):
            # no need to match type here for now
            pass
        elif isinstance(a, (str, z3.SeqRef)) or isinstance(b, (str, z3.SeqRef)):
            a = AbstractString.cast_to_abstract_string(a)
            b = AbstractString.cast_to_abstract_string(b)
        elif isinstance(a, z3.BoolRef) and not isinstance(b, z3.BoolRef):
            a = z3.If(a, 1, 0)
        elif isinstance(b, z3.BoolRef) and not isinstance(a, z3.BoolRef):
            b = z3.If(b, 1, 0)

        # division z3.Int/<anything> is handled as integer division by default
        if isinstance(a, z3.ArithRef) and a.is_int() and op == operator.truediv:
            a = z3.ToReal(a)
        if isinstance(b, z3.ArithRef) and b.is_int() and op == operator.truediv:
            b = z3.ToReal(b)

        # any operation on (z3.Int, float) casts float->int by default
        if isinstance(a, z3.ArithRef) and a.is_int() and isinstance(b, float):
            a = z3.ToReal(a)
        elif isinstance(b, z3.ArithRef) and b.is_int() and isinstance(a, float):
            b = z3.ToReal(b)

        # create an observer variable when handling a comparison (this allows to evaluate its solutions e.g.,  in CHAR)
        if (AbstractDataType.is_abstract(a) or AbstractDataType.is_abstract(b)) \
                and op in AbstractDataType.COMPARISON_OPERATORS:

            # So we call AbstractDatetime operations
            if isinstance(b, (AbstractDatetime)):
                a, b = b, a

            try:
                return solver.get_observer(op(a, b), prefix='observer', z3_type=z3.Bool)
            except z3.z3types.Z3Exception:
                log.warning(f'TYPE MISMATCH IN COMPARISON OPERATION ({type(a).__name__}, {type(b).__name__}), RETURNING FALSE')
                return False
        else:
            return op(a, b)

    @staticmethod
    def process_concrete_operation(a, b, op):
        if b is None:
            return a

        if a is None:
            if type(b) == int:
                a = 0
            elif type(b) == str:
                a = ""
            elif type(b) == bool:
                a = 0
                b = int(b)

        if type(a) == str:
            if type(b) == float:
                b = int(b)
            b = str(b)

        if type(b) == str:
            if type(a) == float:
                a = int(a)
            a = str(a)

        if a == "":
            return b
        elif b == "":
            return a

        try:
            result = op(a, b)
            return result
        except TypeError as e:
            raise RuntimeError(f'Something went wrong during a concrete operation ({e})')


class AbstractDatetime:
    def __init__(self, day=None, month=None, year=None, hour=None, minute=None, second=None):
        super().__init__()

        self.day = day if day is not None else Solver.get_abstract_var(z3.Int, 'day')
        self.month = month if month is not None else Solver.get_abstract_var(z3.Int, 'month')
        self.year = year if year is not None else Solver.get_abstract_var(z3.Int, 'year')
        self.hour = hour if hour is not None else Solver.get_abstract_var(z3.Int, 'hour')
        self.minute = minute if minute is not None else Solver.get_abstract_var(z3.Int, 'minute')
        self.second = second if second is not None else Solver.get_abstract_var(z3.Int, 'second')

    def get_constraints(self):
        constraints = [self.day >= 1, self.day <= 31,
                       self.month >= 1, self.month <= 12,
                       self.year >= 2015, self.year <= 2025,
                       self.hour >= 0, self.hour <= 24,
                       self.minute >= 0, self.minute <= 60,
                       self.second >= 0, self.second <= 60]
        return constraints

    @staticmethod
    def cast_to_time(other):
        if isinstance(other, str):
            try:
                time = datetime.datetime.strptime(other, "%H:%M:%S")
                time = AbstractDatetime(year=0, month=0, day=0, hour=time.hour, minute=time.minute, second=time.second)
            except ValueError:
                return None
        elif isinstance(other, AbstractDatetime):
            time = other
        else:
            raise TypeError("Unsupported operand for AbstractDatetime operation")

        return time

    def __add__(self, other):
        time = AbstractDatetime.cast_to_time(other)

        # note: the correct solution here would be to treat + and & as completely different operation
        if time is None:
            seconds = self.second + 60 * self.minute + 60 * 60 * self.hour
            tstamp = z3.ToReal(seconds) / 86400

            # pass a null solver since we know that won't be used for an ADD operation
            return AbstractDataType.process_abstract_operation(None, tstamp, other, operator.add)

        return AbstractDatetime(year=self.year + time.year,
                                month=self.month + time.month,
                                day=self.day - time.day,
                                hour=self.hour + time.hour,
                                minute=self.minute + time.minute,
                                second=self.second + time.second)

    def __sub__(self, other):
        time = AbstractDatetime.cast_to_time(other)

        return AbstractDatetime(year=self.year - time.year if self.year is not time.year else 0,
                                month=self.month - time.month if self.month is not time.month else 0,
                                day=self.day - time.day if self.day is not time.day else 0,
                                hour=self.hour - time.hour if self.hour is not time.hour else 0,
                                minute=self.minute - time.minute if self.minute is not time.minute else 0,
                                second=self.second - time.second if self.second is not time.second else 0)

    def __eq__(self, other):
        if isinstance(other, bool) or isinstance(other, z3.z3.BoolRef):
            return False

    def __mul__(self, other):
        if not isinstance(other, int):
            raise TypeError("Unsupported operand for AbstractDatetime multiplication")

        log.warning("Calculating AbstractDatetime ignoring day, month, and year")

        seconds = self.second + 60 * self.minute + 60 * 60 * self.hour

        # time is represented as a fraction of the day
        return z3.ToReal(seconds) / 86400 * other


class AbstractChar:
    def __init__(self, ascii_value):
        self.ascii_value = ascii_value
        self.bv_repr = z3.Unit(z3.Int2BV(ascii_value, 8))

    def __add__(self, other):
        new_string = AbstractString([self])
        new_string.chars = new_string.chars + AbstractString.cast_to_abstract_string(other).chars
        return new_string

    def __radd__(self, other):
        new_string = AbstractString([self])
        new_string.chars = AbstractString.cast_to_abstract_string(other).chars + new_string.chars
        return new_string

    def __eq__(self, other):
        return self.ascii_value == other.ascii_value


class AbstractString:
    def __init__(self, chars=None):
        self.chars = chars or []
        self._bv_repr = None

    @staticmethod
    def cast_to_abstract_string(other):
        if isinstance(other, AbstractString):
            return other

        new_string = AbstractString()
        if isinstance(other, z3.ArithRef) and other.is_int():
            new_string.chars = [z3.IntToStr(other)]
        elif isinstance(other, z3.ArithRef) and other.is_real():
            new_string.chars = [z3.IntToStr(z3.ToInt(other))]
        elif isinstance(other, z3.BoolRef):
            new_string.chars = [z3.If(other, z3.StringVal("TRUE"), z3.StringVal("FALSE"))]
        elif isinstance(other, AbstractChar):
            new_string.chars = [other]
        elif isinstance(other, str):
            new_string.chars = list(other)
        elif isinstance(other, z3.SeqRef):
            new_string.chars = [other]
        elif AbstractDataType.is_abstract(other):
            log.error(f'Casting an abstract type ({type(other)}) to str, this could go very bad')
            raise TypeError
        else:
            new_string.chars = list(str(other))

        return new_string

    @property
    def bv_repr(self):
        if self._bv_repr is None and len(self.chars) == 1:
            c = self.chars[0]
            return c.bv_repr if isinstance(c, AbstractChar) else c
        else:
            self._bv_repr = z3.Concat([c.bv_repr if isinstance(c, AbstractChar) else c for c in self.chars])
        return self._bv_repr

    def __add__(self, other):
        # reset the bv representation when it's modified
        self._bv_repr = None

        new_string = AbstractString(self.chars)
        new_string.chars = new_string.chars + AbstractString.cast_to_abstract_string(other).chars
        return new_string

    def __radd__(self, other):
        # reset the bv representation when it's modified
        self._bv_repr = None

        new_string = AbstractString(self.chars)
        new_string.chars = AbstractString.cast_to_abstract_string(other).chars + new_string.chars
        return new_string

    def __eq__(self, other):
        if isinstance(other, bool):
            return False

        if len(self.chars) != len(other.chars):
            return False

        for a, b in zip(self.chars, other.chars):
            if a != b:
                return False

        return True
