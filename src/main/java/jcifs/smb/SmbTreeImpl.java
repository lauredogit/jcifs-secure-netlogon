/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb;


import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.RuntimeCIFSException;
import jcifs.SmbConstants;
import jcifs.SmbTree;
import jcifs.util.transport.TransportException;


class SmbTreeImpl implements SmbTreeInternal {

    private static final Logger log = LoggerFactory.getLogger(SmbTreeImpl.class);

    private static AtomicLong TREE_CONN_COUNTER = new AtomicLong();

    /*
     * 0 - not connected
     * 1 - connecting
     * 2 - connected
     * 3 - disconnecting
     */
    private final AtomicInteger connectionState = new AtomicInteger();

    private final String share;
    private final String service0;
    private final SmbSessionImpl session;

    private volatile int tid;
    private volatile String service = "?????";
    private volatile boolean inDfs, inDomainDfs;
    private volatile long tree_num; // used by SmbFile.isOpen

    private final AtomicLong usageCount = new AtomicLong(0);
    private boolean sessionAcquired = true;

    private final boolean traceResource;
    private final List<StackTraceElement[]> acquires;
    private final List<StackTraceElement[]> releases;


    SmbTreeImpl ( SmbSessionImpl session, String share, String service ) {
        this.session = session.acquire();
        this.share = share.toUpperCase();
        if ( service != null && !service.startsWith("??") ) {
            this.service = service;
        }
        this.service0 = this.service;

        this.traceResource = this.session.getConfig().isTraceResourceUsage();
        if ( this.traceResource ) {
            this.acquires = new LinkedList<>();
            this.releases = new LinkedList<>();
        }
        else {
            this.acquires = null;
            this.releases = null;
        }
    }


    boolean matches ( String shr, String servc ) {
        return this.share.equalsIgnoreCase(shr) && ( servc == null || servc.startsWith("??") || this.service.equalsIgnoreCase(servc) );
    }


    @Override
    public boolean equals ( Object obj ) {
        if ( obj instanceof SmbTreeImpl ) {
            SmbTreeImpl tree = (SmbTreeImpl) obj;
            return matches(tree.share, tree.service);
        }
        return false;
    }


    public SmbTreeImpl acquire () {
        return acquire(true);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.SmbTree#unwrap(java.lang.Class)
     */
    @SuppressWarnings ( "unchecked" )
    @Override
    public <T extends SmbTree> T unwrap ( Class<T> type ) {
        if ( type.isAssignableFrom(this.getClass()) ) {
            return (T) this;
        }
        throw new ClassCastException();
    }


    /**
     * @param track
     * @return tree with increased usage count
     */
    public SmbTreeImpl acquire ( boolean track ) {
        long usage = this.usageCount.incrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Acquire tree " + usage + " " + this);
        }

        if ( track && this.traceResource ) {
            synchronized ( this.acquires ) {
                this.acquires.add(truncateTrace(Thread.currentThread().getStackTrace()));
            }
        }

        if ( usage == 1 ) {
            synchronized ( this ) {
                if ( !this.sessionAcquired ) {
                    log.debug("Reacquire session");
                    this.session.acquire();
                    this.sessionAcquired = true;
                }
            }
        }
        return this;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    public void close () {
        release(false);
    }


    public void release () {
        release(true);
    }


    /**
     * @param track
     */
    public void release ( boolean track ) {
        long usage = this.usageCount.decrementAndGet();
        if ( log.isTraceEnabled() ) {
            log.trace("Release tree " + usage + " " + this);
        }

        if ( track && this.traceResource ) {
            synchronized ( this.releases ) {
                this.releases.add(truncateTrace(Thread.currentThread().getStackTrace()));
            }
        }

        if ( usage == 0 ) {
            synchronized ( this ) {
                log.debug("Usage dropped to zero, release session");
                this.sessionAcquired = false;
                this.session.release();
            }
        }
        else if ( usage < 0 ) {
            log.error("Usage count dropped below zero " + this);
            dumpResource();
            throw new RuntimeCIFSException("Usage count dropped below zero");
        }
    }


    /**
     * @param stackTrace
     * @return
     */
    private static StackTraceElement[] truncateTrace ( StackTraceElement[] stackTrace ) {

        int s = 2;
        int e = stackTrace.length;

        for ( int i = s; i < e; i++ ) {
            StackTraceElement se = stackTrace[ i ];

            if ( i == s && SmbTreeImpl.class.getName().equals(se.getClassName()) && "close".equals(se.getMethodName()) ) {
                s++;
                continue;
            }

            if ( se.getClassName().startsWith("org.junit.runners.") ) {
                e = i - 4;
                break;
            }
        }

        StackTraceElement[] res = new StackTraceElement[e - s];
        System.arraycopy(stackTrace, s, res, 0, e - s);
        return res;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize () throws Throwable {
        if ( isConnected() && this.usageCount.get() != 0 ) {
            log.warn("Tree was not properly released");
        }
    }


    /**
     * 
     * @return whether the tree is connected
     */
    public boolean isConnected () {
        return this.session.isConnected() && this.connectionState.get() == 2;
    }


    /**
     * @return the service
     */
    public String getService () {
        return this.service;
    }


    /**
     * @return the share
     */
    public String getShare () {
        return this.share;
    }


    /**
     * @return the inDfs
     */
    public boolean isInDfs () {
        return this.inDfs;
    }


    /**
     * @return the inDomainDfs
     */
    public boolean isInDomainDfs () {
        return this.inDomainDfs;
    }


    /**
     * @return the session this tree is connected in
     */
    public SmbSessionImpl getSession () {
        return this.session.acquire();
    }


    /**
     * @return the tid
     */
    public int getTid () {
        return this.tid;
    }


    /**
     * @return the tree_num (monotoincally increasing counter to track reconnects)
     */
    public long getTreeNum () {
        return this.tree_num;
    }


    /**
     * 
     */
    void markDomainDfs () {
        this.inDomainDfs = true;
    }


    void markConnected () {
        this.connectionState.set(2);
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        return this.share.hashCode() + 7 * this.service.hashCode();
    }


    void send ( ServerMessageBlock request, ServerMessageBlock response ) throws SmbException {
        send(request, response, Collections.EMPTY_SET);
    }


    void send ( ServerMessageBlock request, ServerMessageBlock response, Set<RequestParam> params ) throws SmbException {
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            synchronized ( transport ) {
                if ( response != null ) {
                    response.received = false;
                }

                // try TreeConnectAndX with the request
                // this does not make any sense if we are disconnecting right now
                if ( ! ( request instanceof SmbComTreeDisconnect ) ) {
                    treeConnect(request, response);
                }
                if ( request == null || ( response != null && response.received ) ) {
                    return;
                }

                // fall trough if the tree connection is already established
                // and send it as a separate request instread

                String svc = this.service;

                if ( svc == null ) {
                    throw new SmbException("Service is null");
                }

                checkRequest(transport, request, svc);
                request.tid = this.tid;
                if ( this.inDfs && !svc.equals("IPC") && request.path != null && request.path.length() > 0 ) {
                    /*
                     * When DFS is in action all request paths are
                     * full UNC paths minus the first backslash like
                     * \server\share\path\to\file
                     * as opposed to normally
                     * \path\to\file
                     */
                    request.flags2 |= SmbConstants.FLAGS2_RESOLVE_PATHS_IN_DFS;
                    request.path = '\\' + transport.tconHostName + '\\' + this.share + request.path;
                }
                try {
                    sess.send(request, response, params);
                }
                catch ( SmbException se ) {
                    if ( se.getNtStatus() == NtStatus.NT_STATUS_NETWORK_NAME_DELETED ) {
                        /*
                         * Someone removed the share while we were
                         * connected. Bastards! Disconnect this tree
                         * so that it reconnects cleanly should the share
                         * reappear in this client's lifetime.
                         */
                        treeDisconnect(true, true);
                    }
                    throw se;
                }
            }
        }
    }


    /**
     * @param transport
     * @param request
     * @throws SmbException
     */
    private static void checkRequest ( SmbTransportImpl transport, ServerMessageBlock request, String svc ) throws SmbException {
        if ( !"A:".equals(svc) ) {
            switch ( request.command ) {
            case ServerMessageBlock.SMB_COM_OPEN_ANDX:
            case ServerMessageBlock.SMB_COM_NT_CREATE_ANDX:
            case ServerMessageBlock.SMB_COM_READ_ANDX:
            case ServerMessageBlock.SMB_COM_WRITE_ANDX:
            case ServerMessageBlock.SMB_COM_CLOSE:
            case ServerMessageBlock.SMB_COM_TREE_DISCONNECT:
                break;
            case ServerMessageBlock.SMB_COM_TRANSACTION:
            case ServerMessageBlock.SMB_COM_TRANSACTION2:
                switch ( ( (SmbComTransaction) request ).subCommand & 0xFF ) {
                case SmbComTransaction.NET_SHARE_ENUM:
                case SmbComTransaction.NET_SERVER_ENUM2:
                case SmbComTransaction.NET_SERVER_ENUM3:
                case SmbComTransaction.TRANS_PEEK_NAMED_PIPE:
                case SmbComTransaction.TRANS_WAIT_NAMED_PIPE:
                case SmbComTransaction.TRANS_CALL_NAMED_PIPE:
                case SmbComTransaction.TRANS_TRANSACT_NAMED_PIPE:
                case SmbComTransaction.TRANS2_GET_DFS_REFERRAL:
                    break;
                default:
                    throw new SmbException("Invalid operation for " + svc + " service: " + request);
                }
                break;
            default:
                throw new SmbException("Invalid operation for " + svc + " service" + request);
            }
        }
    }


    void treeConnect ( ServerMessageBlock andx, ServerMessageBlock andxResponse ) throws SmbException {
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            synchronized ( transport ) {
                if ( waitForState(transport) == 2 ) {
                    // already connected
                    return;
                }
                int before = this.connectionState.getAndSet(1);
                if ( before == 1 ) {
                    // concurrent connection attempt
                    if ( waitForState(transport) == 2 ) {
                        // finished connecting
                        return;
                    }
                    // failure to connect
                    throw new SmbException("Tree disconnected while waiting for connection");
                }
                else if ( before == 2 ) {
                    // concurrently connected
                    return;
                }

                try {
                    /*
                     * The hostname to use in the path is only known for
                     * sure if the NetBIOS session has been successfully
                     * established.
                     */

                    log.debug("Connecting transport");
                    transport.ensureConnected();

                    String unc = "\\\\" + transport.tconHostName + '\\' + this.share;

                    /*
                     * IBM iSeries doesn't like specifying a service. Always reset
                     * the service to whatever was determined in the constructor.
                     */
                    String svc = this.service0;

                    /*
                     * Tree Connect And X Request / Response
                     */

                    if ( log.isTraceEnabled() ) {
                        log.trace("treeConnect: unc=" + unc + ",service=" + svc);
                    }

                    SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(sess.getConfig(), andxResponse);
                    SmbComTreeConnectAndX request = new SmbComTreeConnectAndX(sess, unc, svc, andx);

                    for ( int retries = 0; retries < 1 + sess.getContext().getConfig().getMaxRequestRetries(); retries++ ) {
                        try {
                            sess.send(request, response);
                            break;
                        }
                        catch ( SmbException se ) {
                            if ( se.getCause() instanceof TransportException ) {
                                log.debug("Disconnecting transport for retry");
                                try {
                                    transport.disconnect(true);
                                }
                                catch ( IOException e ) {
                                    se.addSuppressed(e);
                                }
                                continue;
                            }
                            throw se;
                        }
                    }
                    this.tid = response.tid;
                    this.service = response.service;
                    this.inDfs = response.shareIsInDfs;
                    this.tree_num = TREE_CONN_COUNTER.incrementAndGet();

                    this.connectionState.set(2); // connected
                }
                catch ( SmbException se ) {
                    try {
                        treeDisconnect(true, true);
                    }
                    finally {
                        this.connectionState.set(0);
                    }
                    throw se;
                }
                finally {
                    transport.notifyAll();
                }
            }
        }
    }


    /**
     * @param transport
     * @return
     * @throws SmbException
     */
    private int waitForState ( SmbTransportImpl transport ) throws SmbException {
        int cs;
        while ( ( cs = this.connectionState.get() ) != 0 ) {
            if ( cs == 2 ) {
                return cs;
            }
            if ( cs == 3 ) {
                throw new SmbException("Disconnecting during tree connect");
            }
            try {
                log.debug("Waiting for transport");
                transport.wait();
            }
            catch ( InterruptedException ie ) {
                throw new SmbException(ie.getMessage(), ie);
            }
        }
        return cs;
    }


    /**
     * 
     * {@inheritDoc}
     *
     * @see jcifs.smb.SmbTreeInternal#connectLogon(jcifs.CIFSContext)
     */
    @Override
    public void connectLogon ( CIFSContext tf ) throws SmbException {
        if ( tf.getConfig().getLogonShare() == null ) {
            treeConnect(null, null);
        }
        else {
            Trans2FindFirst2 req = new Trans2FindFirst2(tf.getConfig(), "\\", "*", SmbConstants.ATTR_DIRECTORY);
            Trans2FindFirst2Response resp = new Trans2FindFirst2Response(tf.getConfig());
            send(req, resp);
        }
    }


    void treeDisconnect ( boolean inError, boolean inUse ) {
        try ( SmbSessionImpl sess = getSession();
              SmbTransportImpl transport = sess.getTransport() ) {
            synchronized ( transport ) {

                if ( this.connectionState.getAndSet(3) != 2 ) {
                    return;
                }

                long l = this.usageCount.get();
                if ( ( inUse && l != 1 ) || ( !inUse && l > 0 ) ) {
                    log.warn("Disconnected tree while still in use " + this);
                    dumpResource();
                    if ( sess.getConfig().isTraceResourceUsage() ) {
                        throw new RuntimeCIFSException("Disconnected tree while still in use");
                    }
                }

                if ( !inError && this.tid != 0 ) {
                    try {
                        send(new SmbComTreeDisconnect(sess.getConfig()), null);
                    }
                    catch ( SmbException se ) {
                        log.error("SmbComTreeDisconnect failed", se);
                    }
                }
                this.inDfs = false;
                this.inDomainDfs = false;
                this.connectionState.set(0);
                transport.notifyAll();
            }
        }
    }


    /**
     * 
     */
    private void dumpResource () {
        if ( !this.traceResource ) {
            return;
        }

        synchronized ( this.acquires ) {
            for ( StackTraceElement[] acq : this.acquires ) {
                log.debug("Acquire " + Arrays.toString(acq));
            }
        }

        synchronized ( this.releases ) {
            for ( StackTraceElement[] rel : this.releases ) {
                log.debug("Release " + Arrays.toString(rel));
            }
        }
    }


    @Override
    public String toString () {
        return "SmbTree[share=" + this.share + ",service=" + this.service + ",tid=" + this.tid + ",inDfs=" + this.inDfs + ",inDomainDfs="
                + this.inDomainDfs + ",connectionState=" + this.connectionState + ",usage=" + this.usageCount.get() + "]";
    }

}