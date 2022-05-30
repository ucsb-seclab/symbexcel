#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_halt():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.active) == 0

    assert len(simgr.deadended) == 1

    assert simgr.one_deadended.address == 'Macro1!$A$1'

    if common.INTERACTIVE:
        IPython.embed()


def test_char():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=CHAR(65)'),
        'A2': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.memory['Macro1']['A1'].value == 'A'

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_halt()
    test_char()


if __name__ == '__main__':
    common.parse_args()
    main()
