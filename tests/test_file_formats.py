import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def checks(simgr):

    assert simgr.one_deadended.address == 'Macro1!$A$5'

    assert simgr.one_deadended.memory['Macro1']["A3"].value == 5

    assert simgr.one_deadended.memory['Macro1']["A4"].value == 10

    if common.INTERACTIVE:
        IPython.embed()

def test_xls():
    excel_doc = common.get_excel_bin('test_format.xls')
    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)
    checks(simgr)

def test_xlsm():
    excel_doc = common.get_excel_bin('test_format.xlsm')
    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)
    checks(simgr)

def test_xlsb():
    excel_doc = common.get_excel_bin('test_format.xlsb')
    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)
    checks(simgr)


def main():
    test_xls()
    test_xlsm()
    test_xlsb()


if __name__ == '__main__':
    common.parse_args()
    main()
