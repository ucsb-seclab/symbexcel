#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_symbolic():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=GET.WINDOW(5.0)'),
        'A2': ('=', None),
        'A3': ('FORMULA', None),
        'A4': (None, '=CHAR(A1-1052.0)'),
        'A5': ('"BOOM",C1', None),
        'A6': (None, '=CHAR(A1-1051.0)'),
        'A7': (None, '=FORMULA(A2&A3&A4&A5&A6,B1)'),
        'A8': (None, '=GOTO(B1)'),
        'B2': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$B$2'

    assert simgr.one_deadended.memory['Macro1']['B1'].formula == '=FORMULA("BOOM",C1)'

    assert simgr.one_deadended.memory['Macro1']['C1'].value == 'BOOM'

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_symbolic()


if __name__ == '__main__':
    common.parse_args()
    main()
