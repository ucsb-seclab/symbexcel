import logging

log = logging.getLogger(__name__)

class File():

    def __init__(self, filename, perms):
        self.filename = filename
        self.perms    = perms
        self.content  = ""
        self.size     = 0
        self.pos      = 0

    def fwrite(self, content):
        self.content += content or ''
        self.size    += len(content or '')

class FileSystem():

    def __init__(self):
        self.files = []

    def fopen(self, filename, perms):
        self.files.append(File(filename, perms))
        return len(self.files) - 1

    def fsize(self, f):
        return self.files[f].size

    def fwrite(self, f, content):
        if f is None:
            log.error('Writing to a closed file?')
        else:
            self.files[f].fwrite(content)
