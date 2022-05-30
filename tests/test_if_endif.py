#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_if_endif():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=ALERT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=HALT()'),
        'A5': (None, '=ELSE()'),
        'A6': (None, '=HALT()'),
        'A7': (None, '=END.IF()'),
        'A8': (None, '=HALT()'),
        'B1': (0, None),
    })

    simgr = SimulationManager(excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$8'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is True
    assert simgr.one_deadended.memory['Macro1']["A3"].value is False
    assert simgr.one_deadended.memory['Macro1']["A5"].value is False

    if common.INTERACTIVE:
        IPython.embed()


def test_elseif():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=HALT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=ALERT()'),
        'A5': (None, '=ELSE()'),
        'A6': (None, '=HALT()'),
        'A7': (None, '=END.IF()'),
        'A8': (None, '=HALT()'),
        'B1': (6, None),
    })

    simgr = SimulationManager(excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$8'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is False
    assert simgr.one_deadended.memory['Macro1']["A3"].value is True
    assert simgr.one_deadended.memory['Macro1']["A5"].value is False

    if common.INTERACTIVE:
        IPython.embed()


def test_else():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=HALT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=HALT()'),
        'A5': (None, '=ELSE()'),
        'A6': (None, '=ALERT()'),
        'A7': (None, '=END.IF()'),
        'A8': (None, '=HALT()'),
        'B1': (11, None),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$8'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is False
    assert simgr.one_deadended.memory['Macro1']["A3"].value is False
    assert simgr.one_deadended.memory['Macro1']["A5"].value is True

    if common.INTERACTIVE:
        IPython.embed()


def test_endif():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=HALT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=HALT()'),
        'A5': (None, '=END.IF()'),
        'A6': (None, '=HALT()'),
        'B1': (11, None),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$6'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is False
    assert simgr.one_deadended.memory['Macro1']["A3"].value is False
    assert simgr.one_deadended.memory['Macro1']["A5"].value is True

    if common.INTERACTIVE:
        IPython.embed()


def test_nested_if():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=HALT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=IF(FALSE, GOTO(B2),)'),  # should NOT jump to B2
        'A5': (None, '=END.IF()'),
        'A6': (None, '=HALT()'),
        'B1': (6, None),
        'B2': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$6'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is False
    assert simgr.one_deadended.memory['Macro1']["A3"].value is True
    assert simgr.one_deadended.memory['Macro1']["A5"].value is True

    if common.INTERACTIVE:
        IPython.embed()


def test_nested_if_endif():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(B1<5.0)'),
        'A2': (None, '=HALT()'),
        'A3': (None, '=ELSE.IF(B1<10.0)'),
        'A4': (None, '=IF(B1<6.0)'),
        'A5': (None, '=GOTO(B2)'),  # should NOT jump to B2
        'A6': (None, '=END.IF()'),
        'A7': (None, '=END.IF()'),
        'A8': (None, '=HALT()'),
        'B1': (6, None),
        'B2': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$8'

    assert simgr.one_deadended.memory['Macro1']["A1"].value is False
    assert simgr.one_deadended.memory['Macro1']["A3"].value is True
    assert simgr.one_deadended.memory['Macro1']["A4"].value is False
    assert simgr.one_deadended.memory['Macro1']["A6"].value is True
    assert simgr.one_deadended.memory['Macro1']["A7"].value is True

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_if_endif()
    test_elseif()
    test_else()
    test_endif()
    test_nested_if()
    test_nested_if_endif()


if __name__ == '__main__':
    common.parse_args()
    main()
