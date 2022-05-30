#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_define_name_text():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=DEFINE.NAME("name", "text")'),
        'A2': (None, '=FORMULA(name, C1)'),
        'A4': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.memory['Macro1']['C1'].value == 'text'

    if common.INTERACTIVE:
        IPython.embed()


def test_define_name_int():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=DEFINE.NAME("name", 1000)'),
        'A2': (None, '=FORMULA(name, C1)'),
        'A4': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.memory['Macro1']['C1'].value == 1000

    if common.INTERACTIVE:
        IPython.embed()


def test_define_name_bool():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=DEFINE.NAME("name", FALSE)'),
        'A2': (None, '=FORMULA(name, C1)'),
        'A4': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.memory['Macro1']['C1'].value == False

    if common.INTERACTIVE:
        IPython.embed()


def test_define_name_cell():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=DEFINE.NAME("name", B1)'),
        'A2': (None, '=FORMULA(name, C1)'),
        'A3': (None, '=HALT()'),
        'B1': (1000, None),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.defined_names['name'] == simgr.one_deadended.memory['Macro1']['B1']

    assert simgr.one_deadended.memory['Macro1']['C1'].value == 1000

    if common.INTERACTIVE:
        IPython.embed()


# def test_define_name_formula():
#     excel_doc = common.get_excel_doc({
#         'A1': (None, '=DEFINE.NAME("name", "=SUM(R1C2,2,3)")'),
#         'A2': (None, '=FORMULA(name, C1)'),
#         'A3': (None, '=SET.VALUE(B1, 1000)'),
#         'A4': (None, '=FORMULA(name, C2)'),
#         'A5': (None, '=HALT()'),
#
#         'B1': (1, None),
#     })
#
#     simgr = SimulationManager(excel_doc=excel_doc)
#     simgr.run(find=lambda s: s.address in common.BREAKPOINTS)
#
#     assert simgr.one_deadended.memory['Macro1']['C1'].value == 6
#
#     assert simgr.one_deadended.memory['Macro1']['C2'].value == 1005
#
#     if common.INTERACTIVE:
#         IPython.embed()


def test_define_name_arithmetic():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=DEFINE.NAME("name1", 1000)'),
        'A2': (None, '=DEFINE.NAME("name2", 499)'),
        'A3': (None, '=DEFINE.NAME("name3", name1-name2)'),
        'A4': (None, '=DEFINE.NAME("name1", name1-1)'),
        'A5': (None, '=name1+name2'),
        'A6': (None, '=HALT()'),
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert simgr.one_deadended.defined_names['name3'] == 501

    assert simgr.one_deadended.defined_names['name1'] == 999

    assert simgr.one_deadended.memory['Macro1']['A5'].value == 1498

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_define_name_text()
    test_define_name_int()
    test_define_name_bool()
    test_define_name_cell()
    # test_define_name_formula()
    test_define_name_arithmetic()


if __name__ == '__main__':
    common.parse_args()
    main()
