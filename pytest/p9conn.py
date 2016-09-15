#! /usr/bin/env python

"""
handle plan9 server <-> client connections

(We can act as either server or client.)
"""

import logging
import socket
import struct
import sys
import threading
import time

import numalloc
import p9err
import protocol

STD_P9_PORT=564

class P9Error(Exception):
    pass

class RemoteError(P9Error):
    pass

class LocalError(P9Error):
    pass

class TEError(LocalError):
    pass

class P9SockIO(object):
    """
    Common base for server and client, handle send and
    receive to communications channel.  Note that this
    need not set up the channel initially, only the logger.
    The channel is typically connected later.  However, you
    can provide one initially.
    """
    def __init__(self, logger, name=None, server=None, port=STD_P9_PORT):
        self.logger = logger
        self.channel = None
        self.name = name
        self.maxio = None
        self.size_coder = struct.Struct('<I')
        if server is not None:
            self.connect(server, port)
        self.max_payload = 2**32 - self.size_coder.size

    def __str__(self):
        if self.name:
            return self.name
        return repr(self)

    def get_recommended_maxio(self):
        "suggest a max I/O size, for when self.maxio is 0 / unset"
        return 16 * 4096

    def min_maxio(self):
        "return a minimum size below which we refuse to work"
        return self.size_coder.size + 100

    def connect(self, server, port=STD_P9_PORT):
        """
        Connect to given server name / IP address.

        If self.name was none, sets self.name to ip:port on success.
        """
        if self.is_connected():
            raise LocalError('already connected')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.connect((server, port))
        if self.name is None:
            if port == STD_P9_PORT:
                name = server
            else:
                name = '{0}:{1}'.format(server, port)
        else:
            name = None
        self.declare_connected(sock, name, None)

    def is_connected(self):
        "predicate: are we connected?"
        return self.channel != None

    def declare_connected(self, chan, name, maxio):
        """
        Now available for normal protocol (size-prefixed) I/O.
        
        Replaces chan and name and adjusts maxio, if those
        parameters are not None.
        """
        if maxio:
            minio = self.min_maxio()
            if maxio < minio:
                raise LocalError('maxio={0} < minimum {1}'.format(maxio, minio))
        if chan is not None:
            self.channel = chan
        if name is not None:
            self.name = name
        if maxio is not None:
            self.maxio = maxio
            self.max_payload = maxio - self.size_coder.size

    def reduce_maxio(self, maxio):
        "Reduce maximum I/O size per other-side request"
        minio = self.min_maxio()
        if maxio < minio:
            raise LocalError('new maxio={0} < minimum {1}'.format(maxio, minio))
        if maxio > self.maxio:
            raise LocalError('new maxio={0} > current {1}'.format(maxio,
                                                                  self.maxio))
        self.maxio = maxio
        self.max_payload = maxio - self.size_coder.size

    def declare_disconnected(self):
        "Declare comm channel dead (note: leaves self.name set!)"
        self.channel = None
        self.maxio = None

    def shutwrite(self):
        "Do a SHUT_WR on the outbound channel - can't send more"
        chan = self.channel
        # we're racing other threads here
        try:
            chan.shutdown(socket.SHUT_WR)
        except (OSError, AttributeError):
            pass

    def shutdown(self):
        "Shut down comm channel"
        if self.channel:
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            self.channel.close()
            self.declare_disconnected()

    def read(self):
        """
        Try to read a complete packet.

        Returns '' for EOF, as read() usually does.

        If we can't even get the size, this still returns ''.
        If we get a sensible size but are missing some data,
        we can return a short packet.  Since we know if we did
        this, we also return a boolean: True means "really got a
        complete packet."

        Note that '' EOF always returns False: EOF is never a
        complete packet.
        """
        if self.channel is None:
            return b'', False
        size_field = self.xread(self.size_coder.size)
        if len(size_field) < self.size_coder.size:
            if len(size_field) == 0:
                self.logger.log(logging.INFO, '%s: normal EOF', self)
            else:
                self.logger.log(logging.ERROR,
                               '%s: EOF while reading size (got %d bytes)',
                               self, len(size_field))
                # should we raise an error here?
            return b'', False

        size = self.size_coder.unpack(size_field)[0] - self.size_coder.size
        if size <= 0 or size > self.max_payload:
            self.logger.log(logging.ERROR,
                            '%s: incoming size %d is insane '
                            '(max payload is %d)',
                            self, size, self.max_payload)
            # indicate EOF - should we raise an error instead, here?
            return b'', False
        data = self.xread(size)
        return data, len(data) == size

    def xread(self, nbytes):
        """
        Read nbytes bytes, looping if necessary.  Return '' for
        EOF; may return a short count if we get some data, then
        EOF.
        """
        assert nbytes > 0
        # Try to get everything at once (should usually succeed).
        # Return immediately for EOF or got-all-data.
        data = self.channel.recv(nbytes)
        if data == b'' or len(data) == nbytes:
            return data

        # Gather data fragments into an array, then join it all at
        # the end.
        count = len(data)
        data = [data]
        while count < nbytes:
            more = self.channel.recv(nbytes - count)
            if more == b'':
                break
            count += len(more)
            data.append(more)
        return b''.join(data)

    def write(self, data):
        """
        Write all the data, in the usual encoding.  Note that
        the length of the data, including the length of the length
        itself, is already encoded in the first 4 bytes of the
        data.

        Raises IOError if we can't write everything.

        Raises LocalError if len(data) exceeds max_payload.
        """
        size = len(data)
        assert size >= 4
        if size > self.max_payload:
            raise LocalError('data length {0} exceeds '
                             'maximum {1}'.format(size, self.max_payload))
        self.channel.sendall(data)

class P9Client(P9SockIO):
    """
    Act as client.

    We need the a logger (see logging), a timeout, and a protocol
    version to request.  By default, we will downgrade to a lower
    version if asked.

    If server and port are supplied, they are remembered and become
    the default for .connect() (which is still deferred).
    """
    def __init__(self, logger, timeout, version, may_downgrade=True,
                 server=None, port=None):
        super(P9Client, self).__init__(logger)
        self.timeout = timeout
        self.iproto = protocol.p9_version(version)
        self.may_downgrade = may_downgrade
        self.tagalloc = numalloc.NumAlloc(0, 65535)
        self.tagstate = {}
        # The next bit is slighlty dirty: perhaps we should just
        # allocate NOFID out of the 2**32-1 range, so as to avoid
        # "knowing" that it's 2**32-1.
        self.fidalloc = numalloc.NumAlloc(0, protocol.td.NOFID - 1)
        self.live_fids = {}
        self.rootfid = None
        self.rthread = None
        self.lock = threading.Lock()
        self.new_replies = threading.Condition(self.lock)
        self._monkeywrench = {}
        self._server = server
        self._port = port

    def get_monkey(self, what):
        "check for a monkey-wrench"
        with self.lock:
            wrench = self._monkeywrench.get(what)
            if wrench is None:
                return None
            if isinstance(wrench, list):
                # repeats wrench[0] times, or forever if that's 0
                ret = wrench[1]
                if wrench[0] > 0:
                    wrench[0] -= 1
                    if wrench[0] == 0:
                        del self._monkeywrench[what]
            else:
                ret = wrench
                del self._monkeywrench[what]
        return ret

    def set_monkey(self, what, how, repeat=None):
        """
        Set a monkey-wrench.  If repeat is not None it is the number of
        times the wrench is applied (0 means forever, or until you call
        set again with how=None).  What is what to monkey-wrench, which
        depends on the op.  How is generally a replacement value.
        """
        if how is None:
            with self.lock:
                try:
                    del self._monkeywrench[what]
                except KeyError:
                    pass
            return
        if repeat is not None:
            how = [repeat, how]
        with self.lock:
            self._monkeywrench[what] = how

    def get_tag(self):
        "get next available tag ID"
        with self.lock:
            tag = self.tagalloc.alloc()
            if tag is None:
                raise LocalError('all tags in use')
            self.tagstate[tag] = True # ie, in use, still waiting
        return tag

    def set_tag(self, tag, reply):
        "set the reply info for the given tag"
        assert tag >= 0 and tag < 65535
        with self.lock:
            # check whether we're still waiting for the tag
            state = self.tagstate.get(tag)
            if state is True:
                self.tagstate[tag] = reply # i.e., here's the answer
                self.new_replies.notify_all()
                return
            # state must be one of these...
            if state is False:
                # We gave up on this tag.  Reply came anyway.
                self.logger.log(logging.INFO,
                                '%s: got tag %d = %r after timing out on it',
                                self, tag, reply)
                self.retire_tag_locked(tag)
                return
            if state is None:
                # We got a tag back from the server that was not
                # outstanding!
                self.logger.log(logging.WARNING,
                                '%s: got tag %d = %r when tag %d not in use!',
                                self, tag, reply, tag)
                return
            # We got a second reply before handling the first reply!
            self.logger.log(logging.WARNING,
                            '%s: got tag %d = %r when tag %d = %r!',
                            self, tag, reply, tag, state)
            return

    def retire_tag(self, tag):
        "retire the given tag - only used by the thread that handled the result"
        assert tag >= 0 and tag < 65535
        with self.lock:
            self.retire_tag_locked(tag)

    def retire_tag_locked(self, tag):
        "retire the given tag while holding self.lock"
        # must check "in tagstate" because we can race
        # with retire_all_tags.
        if tag in self.tagstate:
            del self.tagstate[tag]
            self.tagalloc.free(tag)

    def retire_all_tags(self):
        "retire all tags, after connection drop"
        with self.lock:
            # release all tags in any state (waiting, answered, timedout)
            self.tagalloc.free_multi(self.tagstate.keys())
            self.tagstate = {}
            self.new_replies.notify_all()

    def alloc_fid(self):
        "allocate new fid"
        with self.lock:
            fid = self.fidalloc.alloc()
            self.live_fids[fid] = True  # XXX
        return fid

    def retire_fid(self, fid):
        "retire one fid"
        with self.lock:
            self.fidalloc.free(fid)
            del self.live_fids[fid]

    def retire_all_fids(self):
        "return live fids to pool"
        with self.lock:
            self.fidalloc.free_multi(self.live_fids.keys())
            self.live_fids = {}         # XXX

    def read_responses(self):
        "Read responses.  This gets spun off as a thread."
        while self.is_connected():
            pkt, is_full = self.read()
            if pkt == b'':
                self.shutwrite()
                self.retire_all_tags()
                return
            if not is_full:
                self.logger.log(logging.WARNING, '%s: got short packet', self)
            try:
                # We have one special case: if we're not yet connected
                # with a version, we must unpack *as if* it's a plain
                # 9P2000 response.
                if self.have_version:
                    resp = self.proto.unpack(pkt)
                else:
                    resp = protocol.plain.unpack(pkt)
            except protocol.SequenceError as err:
                self.logger.log(logging.ERROR, '%s: bad response: %s',
                                self, err)
                try:
                    resp = self.proto.unpack(pkt, noerror=True)
                except protocol.SequenceError:
                    header = self.proto.unpack_header(pkt, noerror=True)
                    self.logger.log(logging.ERROR,
                                    '%s: (not even raw-decodable)', self)
                    self.logger.log(logging.ERROR,
                                    '%s: header decode produced %r',
                                    self, header)
                else:
                    self.logger.log(logging.ERROR,
                                    '%s: raw decode produced %r',
                                    self, resp)
                # after this kind of problem, probably need to
                # shut down, but let's leave that out for a bit
            else:
                # NB: all protocol responses have a "tag",
                # so resp['tag'] always exists.
                self.logger.log(logging.DEBUG, "read_resp: tag %d resp %r", resp.tag, resp)
                self.set_tag(resp.tag, resp)

    def wait_for(self, tag):
        """
        Wait for a response to the given tag.  Return the response,
        releasing the tag.  If self.timeout is not None, wait at most
        that long (and release the tag even if there's no reply), else
        wait forever.

        If this returns None, either the tag was bad initially, or
        a timeout occurred, or the connection got shut down.
        """
        self.logger.log(logging.DEBUG, "wait_for: tag %d", tag)
        if self.timeout is None:
            deadline = None
        else:
            deadline = time.time() + self.timeout
        with self.lock:
            while True:
                # tagstate is True (waiting) or False (timedout) or
                # a valid response, or None if we've reset the tag
                # states (retire_all_tags, after connection drop).
                resp = self.tagstate.get(tag, None)
                if resp is None:
                    # out of sync, exit loop
                    break
                if resp is True:
                    # still waiting for a response - wait some more
                    self.new_replies.wait(self.timeout)
                    if deadline and time.time() > deadline:
                        # Halt the waiting, but go around once more.
                        # Note we may have killed the tag by now though.
                        if tag in self.tagstate:
                            self.tagstate[tag] = False
                    continue
                # resp is either False (timeout) or a reply.
                # If resp is False, change it to None; the tag
                # is now dead until we get a reply (then we
                # just toss the reply).
                # Otherwise, we're done with the tag: free it.
                # In either case, stop now.
                if resp is False:
                    resp = None
                else:
                    self.tagalloc.free(tag)
                    del self.tagstate[tag]
                break
        return resp

    def check_response(self, req, resp):
        """
        This is used to check for a timeout or error response.

        req is the name of the request, and resp is the response
        (which may be None).

        This only returns if resp is not None and is neither
        Rerror nor Rlerror -- the others all raise an error.
        """
        if resp is None:
            self.shutdown()
            raise TEError('{0}: {1}: timeout or EOF'.format(self, req))
        if isinstance(resp, protocol.rrd.Rlerror):
            errno = resp.ecode
            errstr = p9err.dotl_strerror(errno)
            raise RemoteError('{0}: {1}: [Linux error {2}] '
                              '{3}'.format(self, req, errno, errstr))
        if isinstance(resp, protocol.rrd.Rerror):
            errno = resp.errnum
            if errno is not None:
                # it's 9p2000.u, so we want dotu_strerror(errno)
                errstr = p9err.dotu_strerror(errno)
                raise RemoteError('{0}: {1}: [.u error {2}] '
                                  '{3}'.format(self, req, errno, errstr))
            # it's plain 9p, we have just a string
            raise RemoteError('{0}: {1}: {2}'.format(self, req, resp.errstr))

    def badresp(self, req, resp):
        """
        Complain that a response was not something expected.
        """
        self.check_response(req, resp)
        raise LocalError('{0}: {1} got response {2!r}'.format(self, req, resp))

    def connect(self, server=None, port=None):
        """
        Connect to given server/port pair.

        The server and port are remembered.  If given as None,
        the last remembered values are used.  The initial
        remembered values are from the creation of this client
        instance.

        New values are only remembered here on a *successful*
        connect, however.
        """
        if server is None:
            server = self._server
            if server is None:
                raise LocalError('connect: no server specified and no default')
        if port is None:
            port = self._port
            if port is None:
                port = STD_P9_PORT
        self.name = None            # wipe out previous name, if any
        super(P9Client, self).connect(server, port)
        maxio = self.get_recommended_maxio()
        self.declare_connected(None, None, maxio)
        self.proto = self.iproto    # revert to initial protocol
        self.have_version = False
        self.rthread = threading.Thread(target=self.read_responses)
        self.rthread.start()
        tag = self.get_tag()
        req = protocol.rrd.Tversion(tag=tag, msize=maxio,
                                    version=self.get_monkey('version'))
        self.write(self.proto.pack_from(req))
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rversion):
            self.shutdown()
            if isinstance(resp, protocol.rrd.Rerror):
                version = req.version or self.proto.get_version()
                raise RemoteError('{0}: they hated version {1!r}: '
                                  '{2}'.format(self, version, resp.errstr))
            self.badresp('version', resp)
        their_maxio = resp.msize
        try:
            self.reduce_maxio(their_maxio)
        except LocalError as err:
            raise LocalError('{0}: sent maxio={1}, they tried {2}: '
                             '{3}'.format(self, maxio, their_maxio,
                                          err.args[0]))
        if resp.version != self.proto.get_version():
            if not self.may_downgrade:
                self.shutdown()
                raise LocalError('{0}: they only support '
                                 'version {1!r}'.format(self, resp.version))
            # raises LocalError if the version is bad
            # (should we wrap it with a connect-to-{0} msg?)
            self.proto = self.proto.downgrade_to(resp.version)
        self._server = server
        self._port = port
        self.have_version = True

    def attach(self, afid, uname, aname, n_uname):
        """
        Attach.

        Currently we don't know how to do authentication,
        but we'll pass any provided afid through.
        """
        if afid is None:
            afid = protocol.td.NOFID
        if uname is None:
            uname = ''
        if aname is None:
            aname = ''
        if n_uname is None:
            n_uname = protocol.td.NONUNAME
        tag = self.get_tag()
        fid = self.alloc_fid()
        pkt = self.proto.Tattach(tag=tag, fid=fid, afid=afid,
                                 uname=uname, aname=aname,
                                 n_uname=n_uname)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rattach):
            self.badresp('attach', resp)
        # probably should check resp.qid
        self.rootfid = fid

    def shutdown(self):
        "disconnect from server"
        self.retire_all_tags()
        self.retire_all_fids()
        self.rootfid = None
        super(P9Client, self).shutdown()
        if self.rthread:
            self.rthread.join()
            self.rthread = None

    def dupfid(self, fid):
        """
        Copy existing fid to a new fid.
        """
        tag = self.get_tag()
        newfid = self.alloc_fid()
        pkt = self.proto.Twalk(tag=tag, fid=fid, newfid=newfid, nwname=0)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rwalk):
            self.badresp('walk', resp)
        return newfid

    def lookup(self, path, fid=None):
        """
        Do Twalk.  If input fid is not None it is passed through, else
        we use the rootfid.  We allocate the new fid ourselves here.
        Note that if path begins with '/' we use the rootfid even if
        fid is not None.

        There's no logic here to split up long walks (yet?).
        """
        if self.rootfid is None:
            raise LocalError('{0}: not attached'.format(self))
        if path == '/':
            fid = self.rootfid
            components = []
        else:
            components = path.split('/')
            if components[0] == '':
                components = components[1:]
                fid = self.rootfid
            elif fid is None:
                fid = self.rootfid
        tag = self.get_tag()
        newfid = self.alloc_fid()
        pkt = self.proto.Twalk(tag=tag, fid=fid, newfid=newfid,
                               nwname=len(components), wname=components)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rwalk):
            self.badresp('walk', resp)
        return newfid, resp.wqid

    def clunk(self, fid):
        "issue clunk(fid)"
        tag = self.get_tag()
        pkt = self.proto.Tclunk(tag=tag, fid=fid)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rclunk):
            self.badresp('clunk', resp)
        self.retire_fid(fid)

    def remove(self, fid):
        "issue remove (old style), which also clunks fid"
        tag = self.get_tag()
        pkt = self.proto.Tremove(tag=tag, fid=fid)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rremove):
            self.badresp('remove', resp)
        self.retire_fid(fid)

    def mkdir(self, dfid, name, mode, gid):
        "issue mkdir"
        tag = self.get_tag()
        pkt = self.proto.Tmkdir(tag=tag, dfid=dfid, name=name,
                                mode=mode, gid=gid)
        self.write(pkt)
        resp = self.wait_for(tag)
        if not isinstance(resp, protocol.rrd.Rmkdir):
            self.badresp('mkdir', resp)
        return resp.qid
