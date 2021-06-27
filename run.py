import re


class Observer:
    _config = {
        'ignore': []
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
        assert not ({'host', 'port', 'user'} - self.config.keys()), \
            'incorrect connection data, you must specify host port and user'
        try:
            self._config['port'] = int(self._config['port'])
        except ValueError:
            assert 0, 'incorrect port passed'
        assert 'password' in self.config, 'password or ssh keys must be specified'
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


if __name__ == '__main__':
    observer = Observer()
    try:
        observer.validate_config()
    except AssertionError as e:
        observer.error(str(e))
        assert 0
    pass
