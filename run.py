import re
import pysftp
import os
import sys
from beaker.cache import CacheManager
import beaker.util
import hashlib
import argparse
import keyboard
import signal
import asyncio
import time


class Observer:
    _config = {
        'ignore': ['.deploycache'],
        'shortcut-upload': 'ctrl+alt+shift+x',
        'shortcut-cache-clear': 'ctrl+alt+shift+z'
    }
    _cache = None

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    def validate_config(self):
        if 'connect' in self.config:
            reg = re.compile(r'(?P<user>[^@:\s\\]+)@(?P<host>[^@:\s\\]+):(?P<port>\d+)')
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

    def __init__(self, **kwargs):
        self.kwargs = kwargs
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
        path_expr = re.compile(r'''^
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
                            lambda l: re.match(r'^[^#\s]+$', l), lines)))
                        self._config['ignore'].extend(lines)

    @staticmethod
    def warn(message):
        print(f'WARNING: {message}')

    @staticmethod
    def error(message):
        print(f'ERROR: {message}')

    @staticmethod
    def log(message):
        print(message)

    def iter_file(self):
        for root, directories, files in os.walk('.', topdown=True):
            for directory in directories.copy():
                dirpath = os.path.join(root, directory)
                if any(map(lambda ignored: os.path.exists(ignored) and os.path.samefile(ignored, dirpath),
                           self.config['ignore'])):
                    directories.remove(directory)  # excluding directories on the fly possible when topdown=True
            for file in files:
                normpath = os.path.normpath(os.path.join(root, file)).replace('\\', '/')
                if not any(map(lambda ignored: os.path.exists(ignored) and os.path.samefile(ignored, normpath),
                               self.config['ignore'])):
                    if self._file_hash_is_old(normpath):
                        continue
                    yield root, file

    def _setup_connection(self):
        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None
        self.conn = pysftp.Connection(
            host=self.config['host'], port=self.config.get('port', 22), username=self.config['user'],
            password=self.config['password'], cnopts=cnopts
        )

    def _put_one_file(self, local_path, remote_path):
        self.conn.put(local_path, remote_path, callback=lambda sz, fsz: self.log(
            f'TRANSFER {self.config["host"]}: {local_path} {fsz} -> {remote_path} {sz}'))

    def upload(self):
        self._setup_connection()
        tree_cache = set()

        def make_path(dirpath):
            dirpath = os.path.normpath(dirpath).replace('\\', '/')
            if dirpath in tree_cache:
                return
            tree_cache.add(dirpath)
            if self.conn.isdir(dirpath):
                s = ''
                for i in dirpath.split('/'):
                    if not i:
                        continue
                    s += '/' + i
                    tree_cache.add(s)
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

    def _file_hash_is_old(self, normpath):
        cache_dir = os.path.join(os.environ['HOMEPATH'], '.deploy-cache') if sys.platform.find(
            'win') > -1 else '/tmp/.deploy-cache'
        cache_lock_dir = os.path.join(os.environ['HOMEPATH'], '.deploy-cache-lock') if sys.platform.find(
            'win') > -1 else '/tmp/.deploy-cache-lock'
        if not os.path.isdir(cache_dir):
            os.mkdir(cache_dir)
        if not self._cache:
            self._cache = CacheManager(**beaker.util.parse_cache_config_options({
                'cache.type': 'file',
                'cache.data_dir': cache_dir,
                'cache.lock_dir': cache_lock_dir
            }))
        cache = self._cache.get_cache('cache', expire=8 * 3600)
        md5_obj = hashlib.md5()
        with open(normpath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_obj.update(chunk)
        cur_hash = md5_obj.hexdigest()
        if normpath not in cache:
            is_the_same = False
        else:
            old_hash = cache.get(normpath)
            is_the_same = old_hash == cur_hash
        cache.put(normpath, cur_hash)
        return is_the_same

    def clear_cache(self):
        if self._cache:
            cache = self._cache.get_cache('cache', expire=8 * 3600)
            cache.clear()
            self.log('cache cleaned')


class Loop:
    _graceful_exit = False

    def __init__(self):
        exiter = lambda: 0
        for signame in ['SIGINT', 'SIGTERM', 'SIGKILL']:
            signum = getattr(signal, signame, None)
            if signum is None:
                continue
            old_handler = signal.getsignal(signum)
            if not callable(old_handler):
                continue
            exiter = self._graceful_exit_deco(old_handler)
            signal.signal(signum, lambda: None)  # fixme: doesnt catch, dont know why
        keyboard.add_hotkey('ctrl+c', exiter)
        self.observer = Observer()
        keyboard.add_hotkey(self.observer.config['shortcut-upload'], self.proc_for_upload)
        keyboard.add_hotkey(self.observer.config['shortcut-cache-clear'], lambda: self.observer.clear_cache())

        def loop():
            while not self._graceful_exit:
                yield time.sleep(10)  # acceptable
        asyncio.get_event_loop().run_until_complete(loop())

    def _graceful_exit_deco(self, old_handler):
        def new_handler():
            if not self._graceful_exit:
                self.observer.log('Interrupted; wait for clean shutdown; press Ctrl+C again to submit unclean shutdown')
                self._graceful_exit = True
            else:
                return old_handler()
        return new_handler

    def proc_for_upload(self):
        self.observer.upload()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='''Deploy files by sftp in live mode using keyboard shortcuts''')
    # parser.add_argument()
    Loop()
