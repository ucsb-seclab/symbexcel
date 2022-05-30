#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_empty_true_branch():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(GET.WINDOW(2)>10, ,HALT())'),
        'A2': (None, '=ALERT("TRUE BRANCH")'),
        'A3': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc, keep_predecessors=1)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.deadended) == 2

    assert simgr.deadended[1].history[-1].address == 'Macro1!$A$3'

    assert simgr.deadended[0].history[-1].address == 'Macro1!$A$1'

    assert simgr.deadended[0].memory['Macro1']['A1'].value is True

    if common.INTERACTIVE:
        IPython.embed()


def test_empty_false_branch():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(GET.WINDOW(2)>10, HALT(), )'),
        'A2': (None, '=ALERT("TRUE BRANCH")'),
        'A3': (None, '=HALT()'),
        'B1': ('WINDOWS XP', None),
    })

    simgr = SimulationManager(excel_doc=excel_doc, keep_predecessors=1)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.deadended) == 2

    assert simgr.deadended[1].history[-1].address == 'Macro1!$A$3'

    assert simgr.deadended[0].history[-1].address == 'Macro1!$A$1'

    assert simgr.deadended[0].memory['Macro1']['A1'].value is True

    if common.INTERACTIVE:
        IPython.embed()


def test_forced_true_branch():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(ISNUMBER(SEARCH("XP", B1)), ,HALT())'),
        'A2': (None, '=ALERT("TRUE BRANCH")'),
        'A3': (None, '=HALT()'),
        'B1': ('WINDOWS XP', None),
    })

    simgr = SimulationManager(excel_doc=excel_doc, keep_predecessors=1)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.deadended) == 1

    assert simgr.deadended[0].history[-1].address == 'Macro1!$A$3'

    assert simgr.deadended[0].memory['Macro1']['A1'].value == []

    if common.INTERACTIVE:
        IPython.embed()


def test_forced_false_branch():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=IF(ISNUMBER(SEARCH("XP", B1)), ,HALT())'),
        'A2': (None, '=ALERT("TRUE BRANCH")'),
        'A3': (None, '=HALT()'),
        'B1': ('WINDOWS', None),
    })

    simgr = SimulationManager(excel_doc=excel_doc, keep_predecessors=1)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.deadended) == 1

    assert simgr.deadended[0].history[-1].address == 'Macro1!$A$1'

    assert simgr.deadended[0].memory['Macro1']['A1'].value == True

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_empty_true_branch()
    test_empty_false_branch()
    test_forced_true_branch()
    test_forced_false_branch()


if __name__ == '__main__':
    common.parse_args()
    main()
