#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_cell_name_parsing():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=ALERT(B1)'),
        'A2': (None, '=ALERT(R1C2)'),
        'A3': (None, '=ALERT(Macro1!B1)'),
        'A4': (None, '=ALERT(\'Macro1\'!B1)'),
        'A5': (None, '=ALERT(Macro1!R[-4]C[1])'),
        'A6': (None, '=ALERT(\'Macro1\'!R[-5]C[1])'),
        'B1': ('TEST', None),
        'A7': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.address == 'Macro1!$A$7'

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_cell_name_parsing()


if __name__ == '__main__':
    common.parse_args()
    main()
