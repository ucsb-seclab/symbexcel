#!/usr/bin/env python3

import IPython
import z3

from symbexcel import SimulationManager
from symbexcel.abstract import AbstractDatetime

if __package__:
    from . import common
else:
    import common


def test_time():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=NOW()'),
        'A2': (None, '=NOW()+"00:00:02"'),
        'A3': (None, '=DAY(NOW()+"00:00:02")'),
        'A4': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.deadended) == 1

    assert simgr.deadended[0].address == 'Macro1!$A$4'

    assert isinstance(simgr.deadended[0].memory['Macro1']['A1'].value, AbstractDatetime)

    assert isinstance(simgr.deadended[0].memory['Macro1']['A2'].value, AbstractDatetime)

    assert isinstance(simgr.deadended[0].memory['Macro1']['A3'].value, z3.ArithRef)

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_time()


if __name__ == '__main__':
    common.parse_args()

    main()
