#! /usr/bin/env python

"""
Run various tests, as a client.
"""

from __future__ import print_function

import argparse
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
import functools
import logging
import socket
import struct
import sys
import time
import traceback

import p9conn
import protocol

LocalError = p9conn.LocalError
RemoteError = p9conn.RemoteError
TEError = p9conn.TEError

class TestState(object):
    def __init__(self):
        self.config = None
        self.logger = None
        self.successes = 0
        self.skips = 0
        self.failures = 0
        self.exceptions = 0
        self.clnt_tab = {}
        self.mkclient = None

    def ccc(self, cid=None):
        """
        Connect or reconnect as client (ccc = check and connect client).

        If caller provides a cid (client ID) we check that specific
        client.  Otherwise the default ID ('base') is used.
        In any case we return the now-connected client, plus the
        attachment (session info) if any.
        """
        if cid is None:
            cid = 'base'
        pair = self.clnt_tab.get(cid)
        if pair is None:
            clnt = self.mkclient()
            pair = [clnt, None]
            self.clnt_tab[cid] = pair
        else:
            clnt = pair[0]
        if not clnt.is_connected():
            clnt.connect()
        return pair

    def dcc(self, cid=None):
        """
        Disconnect client (disconnect checked client).  If no specific
        client ID is provided, this disconnects ALL checked clients!
        """
        if cid is None:
            for cid in list(self.clnt_tab.keys()):
                self.dcc(cid)
        pair = self.clnt_tab.get(cid)
        if pair is not None:
            clnt = pair[0]
            if clnt.is_connected():
                clnt.shutdown()
            del self.clnt_tab[cid]

    def ccs(self, cid=None):
        """
        Like ccc, but establish a session as well, by setting up
        the uname/n_uname.

        Return the client instance (only).
        """
        pair = self.ccc(cid)
        clnt = pair[0]
        if pair[1] is None:
            # No session yet - establish one.  Note, this may fail.
            section = None if cid is None else ('client-' + cid)
            aname = getconf(self.config, section, 'aname', '')
            uname = getconf(self.config, section, 'uname', '')
            if clnt.proto > protocol.plain:
                n_uname = getint(self.config, section, 'n_uname', 1001)
            else:
                n_uname = None
            clnt.attach(afid=None, aname=aname, uname=uname, n_uname=n_uname)
            pair[1] = (aname, uname, n_uname)
        return clnt

def getconf(conf, section, name, default=None, rtype=str):
    """
    Get configuration item for given section, or for "client" if
    there is no entry for that particular section (or if section
    is None).

    This lets us get specific values for specific tests or
    groups ([foo] name=value), falling back to general values
    ([client] name=value).

    The type of the returned value <rtype> can be str, int, bool,
    or float.  The default is str (and see getconfint, getconfbool,
    getconffloat below).

    A default value may be supplied; if it is, that's the default
    return value (this default should have the right type).  If
    no default is supplied, a missing value is an error.
    """
    try:
        # note: conf.get(None, 'foo') raises NoSectionError
        where = section
        result = conf.get(where, name)
    except (configparser.NoSectionError, configparser.NoOptionError):
        try:
            where = 'client'
            result = conf.get(where, name)
        except configparser.NoSectionError:
            sys.exit('no [{0}] section in configuration!'.format(where))
        except configparser.NoOptionError:
            if default is not None:
                return default
            if section is not None:
                where = '[{0}] or [{1}]'.format(section, where)
            else:
                where = '[{0}]'.format(where)
            raise LocalError('need {0}=value in {1}'.format(name, where))
    where = '[{0}]'.format(where)
    if rtype is str:
        return result
    if rtype is int:
        return int(result)
    if rtype is float:
        return float(result)
    if rtype is bool:
        if result.lower() in ('1', 't', 'true', 'y', 'yes'):
            return True
        if result.lower() in ('0', 'f', 'false', 'n', 'no'):
            return False
        raise ValueError('{0} {1}={2}: invalid boolean'.format(where, name,
                                                              result))
    raise ValueError('{0} {1}={2}: internal error: bad result type '
                     '{3!r}'.format(where, name, result, rtype))

def getint(conf, section, name, default=None):
    "get integer config item"
    return getconf(conf, section, name, default, int)

def getfloat(conf, section, name, default=None):
    "get float config item"
    return getconf(conf, section, name, default, float)

def getbool(conf, section, name, default=None):
    "get boolean config item"
    return getconf(conf, section, name, default, bool)

def pluralize(n, singular, plural):
    "return singular or plural based on value of n"
    return plural if n != 1 else singular

class TCDone(Exception):
    "used in succ/fail/skip - skips rest of testcase with"
    pass

class TestCase(object):
    """
    Start a test case.  Most callers must then do a ccs() to connect.

    A failed test will generally disconnect from the server; a
    new ccs() will reconnect, if the server is still alive.
    """
    def __init__(self, name, tstate, special_connect=False):
        self.name = name
        self.status = None
        self.detail = None
        self.tstate = tstate
        self._shutdown = None

    def auto_disconnect(self, conn):
        self._shutdown = conn

    def succ(self, detail=None):
        "set success status"
        self.status = 'SUCC'
        self.detail = detail
        raise TCDone()

    def fail(self, detail):
        "set failure status"
        self.status = 'FAIL'
        self.detail = detail
        raise TCDone()

    def skip(self, detail=None):
        "set skip status"
        self.status = 'SKIP'
        self.detail = detail
        raise TCDone()

    def ccs(self):
        "call tstate ccs, turn socket.error connect failure into test fail"
        try:
            self.detail = 'connecting'
            ret = self.tstate.ccs()
            self.detail = None
            return ret
        except socket.error as err:
            self.fail(str(err))

    def __enter__(self):
        self.tstate.logger.log(logging.DEBUG, 'ENTER: %s', self.name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        tstate = self.tstate
        eat_exc = False
        tb_detail = None
        if exc_type is TCDone:
            # we exited with succ, fail, or skip
            eat_exc = True
            exc_type = None
        if exc_type is not None:
            if self.status is None:
                self.status = 'EXCP'
            else:
                self.status += ' EXC'
            if exc_type == TEError:
                # timeout/eof - best guess is that we crashed the server!
                eat_exc = True
                tb_detail = ['timeout or EOF']
            elif exc_type in (socket.error, RemoteError, LocalError):
                eat_exc = True
                tb_detail = traceback.format_exception(exc_type, exc_val,
                                                       exc_tb)
            level = logging.ERROR
            tstate.failures += 1
            tstate.exceptions += 1
        else:
            if self.status is None:
                self.status = 'SUCC'
            if self.status == 'SUCC':
                level = logging.INFO
                tstate.successes += 1
            elif self.status == 'SKIP':
                level = logging.INFO
                tstate.skips += 1
            else:
                level = logging.ERROR
                tstate.failures += 1
        tstate.logger.log(level, '%s: %s', self.status, self.name)
        if self.detail:
            tstate.logger.log(level, '      detail: %s', self.detail)
        if tb_detail:
            for line in tb_detail:
                tstate.logger.log(level, '      %s', line.rstrip())
        if self._shutdown:
            self._shutdown.shutdown()
        return eat_exc

def main():
    "the usual main"
    parser = argparse.ArgumentParser(description='run tests against a server')

    parser.add_argument('-c', '--config',
        action='append',
        help='specify additional file(s) to read (beyond testconf.ini)')

    args = parser.parse_args()
    config = configparser.SafeConfigParser()
    # use case sensitive keys
    config.optionxform = str

    try:
        with open('testconf.ini', 'r') as stream:
            config.readfp(stream)
    except (OSError, IOError) as err:
        sys.exit(str(err))
    if args.config:
        ok = config.read(args.config)
        failed = set(ok) - set(args.config)
        if len(failed):
            nfailed = len(failed)
            word = 'files' if nfailed > 1 else 'file'
            failed = ', '.join(failed)
            print('failed to read {0} {1}: {2}'.format(nfailed, word, failed))
            sys.exit(1)

    logging.basicConfig(level=config.get('client', 'loglevel').upper())
    logger = logging.getLogger(__name__)
    tstate = TestState()
    tstate.logger = logger
    tstate.config = config

    server = config.get('client', 'server')
    port = config.getint('client', 'port')
    proto = config.get('client', 'protocol')
    may_downgrade = config.getboolean('client', 'may_downgrade')
    timeout = config.getfloat('client', 'timeout')

    keep_going = False
    with TestCase('send bad packet', tstate) as tc:
        tc.detail = 'connecting to {0}:{1}'.format(server, port)
        try:
            conn = p9conn.P9SockIO(logger, server=server, port=port)
        except socket.error as err:
            tc.fail('cannot connect at all (server down?)')
        tc.auto_disconnect(conn)
        tc.detail = None
        pkt = struct.pack('<I', 256);
        conn.write(pkt)
        # ignore reply if any, we're just trying to trip the server
        keep_going = True
        tc.succ()

    if keep_going:
        tstate.mkclient = functools.partial(p9conn.P9Client, logger,
                                           timeout, proto, may_downgrade,
                                           server=server, port=port)
        with TestCase('send bad Tversion', tstate) as tc:
            try:
                clnt = tstate.mkclient()
            except socket.error as err:
                tc.fail('can no longer connect, did bad pkt crash server?')
            tc.auto_disconnect(clnt)
            clnt.set_monkey('version', 'wrongo, fishbreath!')
            tc.detail = 'connecting'
            try:
                clnt.connect()
            except RemoteError as err:
                keep_going = True
                tc.succ(err.args[0])
            tc.fail('server accepted a bad Tversion')

    if keep_going:
        with TestCase('connect normally', tstate) as tc:
            tc.detail = 'connecting'
            try:
                tstate.ccc()
            except RemoteError as err:
                # can't test any further, but this might be success
                keep_going = False
                if 'they only support version' in err.args[0]:
                    tc.succ(err.args[0])
                tc.fail(err.args[0])
            tc.succ()

    if keep_going:
        with TestCase('attach with bad afid', tstate) as tc:
            clnt = tstate.ccc()[0]
            section = 'attach-with-bad-afid'
            aname = getconf(tstate.config, section, 'aname', '')
            uname = getconf(tstate.config, section, 'uname', '')
            if clnt.proto > protocol.plain:
                n_uname = getint(tstate.config, section, 'n_uname', 1001)
            else:
                n_uname = None
            try:
                clnt.attach(afid=42, aname=aname, uname=uname, n_uname=n_uname)
            except RemoteError as err:
                tc.succ(err.args[0])
            tc.dcc()
            tc.fail('bad attach afid not rejected')
    try:
        if keep_going:
            more_test_cases(tstate)
    finally:
        tstate.dcc()

    n_tests = tstate.successes + tstate.failures
    print('summary:')
    if tstate.successes:
        print('{0}/{1} tests succeeded'.format(tstate.successes, n_tests))
    if tstate.failures:
        print('{0}/{1} tests failed'.format(tstate.failures, n_tests))
    if tstate.skips:
        print('{0} {1} skipped'.format(tstate.skips,
                                       pluralize(tstate.skips,
                                                 'test', 'tests')))
    if tstate.exceptions:
        print('{0} {1} occurred'.format(tstate.exceptions,
                                       pluralize(tstate.exceptions,
                                                 'exception', 'exceptions')))
    return 0 # if tstate.failures == 0 else 1

def more_test_cases(tstate):
    "run cases that can only proceed if connecting works at all"
    with TestCase('attach normally', tstate) as tc:
        tc.ccs()
        tc.succ()

    with TestCase('empty string in Twalk request', tstate) as tc:
        clnt = tc.ccs()
        try:
            fid, qid = clnt.lookup('//')
        except RemoteError as err:
            tc.succ(err.args[0])
        tc.fail('empty wname not rejected')

    with TestCase('rename adjusts other fids', tstate) as tc:
        clnt = tc.ccs()
        if clnt.proto < protocol.dotl or True:
            tc.skip('applies only to 9P2000.L')
        fid, qid = clnt.lookup('/')
        if qid.type != protocol.rrd.QTDIR:
            tc.fail('/ is not a directory')
        clnt.mkdir(fid, 'dir')
        fid, qid = clnt.lookup('dir', fid)
        if qid.type != protocol.rrd.QTDIR:
            tc.fail('/dir is not a directory')
        tc.succ()

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit('\nInterrupted')
