#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_minimal():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=--+-+ALERT()-+-ALERT()'),
        #'A1': (None, '=ABSREF("R[-2]C[-2]", C3)'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_minimal()


if __name__ == '__main__':
    common.parse_args()
    main()
