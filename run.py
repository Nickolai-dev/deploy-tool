import re
import pysftp
import os

TESTING_OFFLINE = True


# class OfflineTesting:
#     def __init__(self) -> None:
#         pass

#     def put(self, local_path, remote_path):
#         os.path.


class Observer:
    _config = {
        'ignore': ['.deploycache']
    }

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    def validate_config(self):
        if 'connect' in self.config:
            reg = re.compile(r'(?P<user>[^\@:\s\\]+)\@(?P<host>[^\@:\s\\]+):(?P<port>\d+)')
            match = reg.match(self.config.get('connect'))
            assert match, 'incorrect connection data'
            self._config.update(match.groupdict())
        assert not ({'host', 'user'} - self.config.keys()), \
            'incorrect connection data, you must specify host port and user'
        try:
            if self.config.get('port'):
                self._config['port'] = int(self._config['port'])
        except ValueError:
            assert 0, 'incorrect port passed'
        assert 'password' in self.config, 'password or ssh keys must be specified'
        assert 'deployPath' in self.config, 'deploy path is not specified'
        password_in_source = re.match(r'source\s+(?P<filename>\S+)', self.config['password'])
        if password_in_source:
            try:
                with open(password_in_source.groupdict().get('filename')) as password_source:
                    self._config.update({'password': password_source.read()})
            except FileNotFoundError:
                raise AssertionError('password source file is missing')

    def __init__(self):
        try:
            with open('./deploy.config') as config:
                self.parse_config(config)
        except FileNotFoundError:
            raise FileNotFoundError('deploy.config file is missng in current directory')
        try:
            self.validate_config()
        except AssertionError as e:
            self.error(str(e))
            raise RuntimeError('config file validation failed')

    def parse_config(self, file):
        base_expr = re.compile(r'''^
            (?:\s+) |  # empty line
            (?P<ignore>:ignore) |  # ignore files open tag
            (?P<endignore>:endignore) |  # ignore files close tag
            (?:(?P<commentline>\#[^\n]+)) |  # full comment line
            (?:(?P<key>[\d\w]+)\s+(?P<value>[^\n]+))  # base
        \s*$''', re.VERBOSE)
        path_expr = re.compile('''^
            (?:\s+) |  # empty line
            (?P<ignore>:ignore) |  # ignore files open tag
            (?P<endignore>:endignore) |  # ignore files close tag
            (?:source\s+(?P<pathsource>\S+)) |  # pathes source
            (?P<path>\S+)  # one path
        \s*$''', re.VERBOSE)
        i = 0
        while True:
            line = file.readline()
            if not line:
                break
            i += 1
            match = base_expr.match(line)
            if not match:
                self.warn(f'cannot read line {i} in config file {file.name}')
                continue
            if match.groupdict()['key']:
                self._config.update({
                    match.groupdict()['key']: match.groupdict()['value']
                })
            if match.groupdict()['ignore']:
                while True:
                    line = file.readline()
                    if not line:
                        break
                    i += 1
                    match = path_expr.match(line)
                    if not match:
                        self.warn(f'cannot read line {i} in config file {file.name}')
                        continue
                    if match.groupdict()['endignore']:
                        break
                    if match.groupdict()['path']:
                        self._config['ignore'].append(match.groupdict()['path'])
                    if match.groupdict()['pathsource']:
                        with open(match.groupdict()['pathsource']) as pathsource:
                            lines = pathsource.readlines()
                        lines = list(map(lambda n: n[:-1] if n[-1] == '\n' else n, filter(
                            lambda l: re.match(r'^[^\#\s]+$', l), lines)))
                        self._config['ignore'].extend(lines)

    @staticmethod
    def warn(message):
        print(f'WARNING: {message}')

    @staticmethod
    def error(message):
        print(f'ERROR: {message}')

    @staticmethod
    def log(message):
        print(f'{message}')

    def iter_file(self):
        # yield '.', 'run.py'  # todo
        # return
        for root, directories, files in os.walk('.', topdown=True):
            for directory in directories.copy():
                dirpath = os.path.join(root, directory)
                if any(map(lambda ignored: os.path.exists(ignored) and os.path.samefile(ignored, dirpath), self.config['ignore'])):
                    directories.remove(directory)  # excluding directories on the fly possible when topdown=True
            for file in files:
                normpath = os.path.normpath(os.path.join(root, file)).replace('\\', '/')
                if not any(map(lambda ignored: os.path.exists(ignored) and os.path.samefile(ignored, normpath), self.config['ignore'])):
                    yield root, normpath
    
    def _setup_connection(self):
        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None
        # if not TESTING_OFFLINE:
        self.conn = pysftp.Connection(
            host=self.config['host'], port=self.config.get('port', 22), username=self.config['user'],
            password=self.config['password'], cnopts=cnopts
        )
        # else:
        #     self.conn = os.path
    
    def _put_one_file(self, local_path, remote_path):
        self.conn.put(local_path, remote_path, callback=lambda: self.log(f'TRANSFER {self.config["host"]}: {local_path} -> {remote_path}'))

    def upload(self):
        tree_cache = []

        def make_path(dirpath):
            dirpath = os.normpath(dirpath).replace('\\', '/')
            if dirpath in tree_cache:
                return
            tree_cache.append(dirpath)
            if self.conn.isdir(dirpath):
                return
            top = '/'.join(dirpath.split('/')[:-1])
            if top not in ['', '.']:
                make_path(top)
            self.conn.mkdir(dirpath)
        for relative_local_path, filename in self.iter_file():
            make_path(os.path.normpath(os.path.join(self.config['deployPath'], relative_local_path)).replace('\\', '/'))
            lp = os.path.join(relative_local_path, filename).replace('\\', '/')
            rp = os.path.normpath(
                os.path.join(self.config['deployPath'], relative_local_path, filename)).replace('\\', '/')
            self._put_one_file(lp, rp)
        self.conn.close()


if __name__ == '__main__':
    observer = Observer()
    # observer.upload()
    for item in observer.iter_file():
        print(item)
    pass
