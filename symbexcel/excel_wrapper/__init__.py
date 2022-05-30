import logging
import msoffcrypto
import tempfile
import os

from .excel_wrapper import ExcelWrapper, RowAttribute
from .xls_wrapper   import XLSWrapper
from .xlsb_wrapper  import XLSBWrapper
from .xlsm_wrapper  import XLSMWrapper
from .com_wrapper  import COMWrapper

log = logging.getLogger(__name__)


def decrypt(file_path):
    msoffcrypto_obj = msoffcrypto.OfficeFile(open(file_path, "rb"))
    if msoffcrypto_obj.is_encrypted():
        msoffcrypto_obj.load_key(password='VelvetSweatshop')
        tmp_file_handle, new_file_path = tempfile.mkstemp()
        with os.fdopen(tmp_file_handle, 'wb') as f:
            msoffcrypto_obj.decrypt(f)

        return new_file_path

    return file_path

def parse_excel_doc(file_path, com=False, nocache=False):
    try:
        file_path = decrypt(file_path)
    except msoffcrypto.exceptions.FileFormatError:
        pass

    if com:
        return COMWrapper(file_path, nocache)

    file_type = ExcelWrapper.get_file_type(file_path)

    if file_type is None:
        raise Exception('Input file type is not supported.')

    if file_type == 'xls':
        log.info('Parsing XLS file')
        return XLSWrapper(file_path)
    elif file_type == 'xlsm':
        log.info('Parsing XLSM file')
        return XLSMWrapper(file_path)
    elif file_type == 'xlsb':
        log.info('Parsing XLSB file')
        return XLSBWrapper(file_path)

    raise Exception('Input file type is not supported.')
