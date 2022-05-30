#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_minimal():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=GOTO(B1)'),
        'B1': (None, '=GET.WORKSPACE(1.0)'),
        'B2': (None, '=FORMULA(B1,C1)'),
        'B3': (None, '=ALERT(C1)'),
        'B4': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$B$4'

    assert simgr.one_deadended.memory['Macro1']['B1'].value == simgr.one_deadended.memory['Macro1']['C1'].value

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_minimal()


if __name__ == '__main__':
    common.parse_args()
    main()
