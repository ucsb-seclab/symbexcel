#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


def test_goto():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=GOTO(B1)'),
        'B1': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.active) == 0

    assert len(simgr.deadended) == 1

    assert simgr.one_deadended.address == 'Macro1!$B$1'

    if common.INTERACTIVE:
        IPython.embed()


def test_run():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=RUN(B1)'),
        'B1': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)
    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.active) == 0

    assert len(simgr.deadended) == 1

    assert simgr.one_deadended.address == 'Macro1!$B$1'

    # calling RUN should push the next address into the subroutine stack (call stack)
    assert len(simgr.one_deadended.subroutine_stack) == 1
    assert simgr.one_deadended.subroutine_stack.pop() == ('Macro1', 'A', 2)

    if common.INTERACTIVE:
        IPython.embed()


def test_on_time():
    excel_doc = common.get_excel_doc({
        'A1': (None, '=ON.TIME(NOW(), fdsaf)'),
        'B1': (None, '=HALT()')
    })

    simgr = SimulationManager(excel_doc=excel_doc)

    excel_doc.get_defined_names()
    excel_doc._defined_names['fdsaf'] = simgr.one_active.memory['Macro1']['B1']

    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len(simgr.active) == 0

    assert len(simgr.deadended) == 1

    assert simgr.one_deadended.address == 'Macro1!$B$1'

    # calling ON.TIME should push the next address into the subroutine stack (call stack)
    assert len(simgr.one_deadended.subroutine_stack) == 1
    assert simgr.one_deadended.subroutine_stack.pop() == ('Macro1', 'A', 2)

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_goto()
    test_run()
    test_on_time()


if __name__ == '__main__':
    common.parse_args()
    main()
