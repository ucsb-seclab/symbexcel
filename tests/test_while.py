#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_while():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=WHILE(A2<5.0)'),
        'A2': (0, '=SUM(A2, 1)'),
        'A3': (None, '=NEXT()'),
        'A4': (0, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$4'

    assert simgr.one_deadended.memory['Macro1']["A2"].value == 5

    if common.INTERACTIVE:
        IPython.embed()


def test_false_while():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=WHILE(A2 > 100)'),
        'A2': (1, '=SUM(A2, 1)'),
        'A3': (None, '=NEXT()'),
        'A4': (0, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.memory['Macro1']["A2"].value == 1

    if common.INTERACTIVE:
        IPython.embed()


def test_nested_while():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=WHILE(A2<2)'),
        'A2': (0, '=SUM(A2, 1)'),

        'A3': (None, '=SET.VALUE(A5, 0)'),
        'A4': (None, '=WHILE(A5<3)'),
        'A5': (0, '=SUM(A5, 1)'),
        'A6': (0, '=SUM(A6, 1)'),
        'A7': (None, '=NEXT()'),

        'A8': (None, '=NEXT()'),
        'A9': (0, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$9'

    assert simgr.one_deadended.memory['Macro1']["A2"].value == 2

    assert simgr.one_deadended.memory['Macro1']["A5"].value == 3

    assert simgr.one_deadended.memory['Macro1']["A6"].value == 6

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_while()
    test_false_while()
    test_nested_while()


if __name__ == '__main__':
    common.parse_args()
    main()
