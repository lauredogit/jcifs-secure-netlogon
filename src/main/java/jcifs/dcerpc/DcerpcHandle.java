/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                   "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;


import java.io.IOException;
import java.net.MalformedURLException;
import java.util.concurrent.atomic.AtomicInteger;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;


/**
 *
 *
 */
public abstract class DcerpcHandle implements DcerpcConstants, AutoCloseable {

    /*
     * Bindings are in the form:
     * proto:\\server[key1=val1,key2=val2]
     * or
     * proto:server[key1=val1,key2=val2]
     * or
     * proto:[key1=val1,key2=val2]
     *
     * If a key is absent it is assumed to be 'endpoint'. Thus the
     * following are equivalent:
     * proto:\\ts0.win.net[endpoint=\pipe\srvsvc]
     * proto:ts0.win.net[\pipe\srvsvc]
     *
     * If the server is absent it is set to "127.0.0.1"
     */
    protected static DcerpcBinding parseBinding ( String str ) throws DcerpcException {
        int state, mark, si;
        char[] arr = str.toCharArray();
        String proto = null, key = null;
        DcerpcBinding binding = null;

        state = mark = si = 0;
        do {
            char ch = arr[ si ];

            switch ( state ) {
            case 0:
                if ( ch == ':' ) {
                    proto = str.substring(mark, si);
                    mark = si + 1;
                    state = 1;
                }
                break;
            case 1:
                if ( ch == '\\' ) {
                    mark = si + 1;
                    break;
                }
                state = 2;
            case 2:
                if ( ch == '[' ) {
                    String server = str.substring(mark, si).trim();
                    if ( server.length() == 0 ) {
                        // this can also be a v6 address within brackets, look ahead required
                        int nexts = str.indexOf('[', si + 1);
                        int nexte = str.indexOf(']', si);
                        if ( nexts >= 0 && nexte >= 0 && nexte == nexts - 1 ) {
                            server = str.substring(si, nexte + 1);
                            si = nexts;
                        }
                        else {
                            server = "127.0.0.1";
                        }
                    }
                    binding = new DcerpcBinding(proto, server);
                    mark = si + 1;
                    state = 5;
                }
                break;
            case 5:
                if ( ch == '=' ) {
                    key = str.substring(mark, si).trim();
                    mark = si + 1;
                }
                else if ( ch == ',' || ch == ']' ) {
                    String val = str.substring(mark, si).trim();
                    mark = si + 1;
                    if ( key == null )
                        key = "endpoint";
                    if ( binding != null ) {
                        binding.setOption(key, val);
                    }
                    key = null;
                }
                break;
            default:
                si = arr.length;
            }

            si++;
        }
        while ( si < arr.length );

        if ( binding == null || binding.getEndpoint() == null )
            throw new DcerpcException("Invalid binding URL: " + str);

        return binding;
    }

    private static final AtomicInteger call_id = new AtomicInteger(1);

    private final DcerpcBinding binding;
    private int max_xmit = 4280;
    private int max_recv = this.max_xmit;
    private int state = 0;
    private DcerpcSecurityProvider securityProvider = null;
    private CIFSContext transportContext;


    /**
     * @param tc
     *
     */
    public DcerpcHandle ( CIFSContext tc ) {
        this.transportContext = tc;
        this.binding = null;
    }


    /**
     * @param tc
     * @param binding
     */
    public DcerpcHandle ( CIFSContext tc, DcerpcBinding binding ) {
        this.transportContext = tc;
        this.binding = binding;
    }


    /**
     * @return the binding
     */
    public DcerpcBinding getBinding () {
        return this.binding;
    }


    /**
     * @return the max_recv
     */
    int getMaxRecv () {
        return this.max_recv;
    }


    /**
     * @return the max_xmit
     */
    int getMaxXmit () {
        return this.max_xmit;
    }


    /**
     * Get a handle to a service
     *
     * @param url
     * @param tc
     *            context to use
     * @return a DCERPC handle for the given url
     * @throws MalformedURLException
     * @throws DcerpcException
     */
    public static DcerpcHandle getHandle ( String url, CIFSContext tc ) throws MalformedURLException, DcerpcException {
        return getHandle(url, tc, false);
    }


    /**
     * Get a handle to a service
     *
     * @param url
     * @param tc
     * @param unshared
     *            whether an exclusive connection should be used
     * @return a DCERPC handle for the given url
     * @throws MalformedURLException
     * @throws DcerpcException
     */
    public static DcerpcHandle getHandle ( String url, CIFSContext tc, boolean unshared ) throws MalformedURLException, DcerpcException {
        if ( url.startsWith("ncacn_np:") ) {
            return new DcerpcPipeHandle(url, tc, unshared);
        }
        throw new DcerpcException("DCERPC transport not supported: " + url);
    }


    /**
     * Bind the handle
     *
     * @throws DcerpcException
     * @throws IOException
     */
    public void bind () throws DcerpcException, IOException {
        synchronized ( this ) {
            try {
                this.state = 1;
                DcerpcMessage bind = new DcerpcBind(this.binding, this);
                sendrecv(bind);
            }
            catch ( IOException ioe ) {
                this.state = 0;
                throw ioe;
            }
        }
    }


    /**
     *
     * @param msg
     * @throws DcerpcException
     * @throws IOException
     */
    public void sendrecv ( DcerpcMessage msg ) throws DcerpcException, IOException {
        if ( this.state == 0 ) {
            bind();
        }
        byte[] inB = this.transportContext.getBufferCache().getBuffer();
        byte[] out = this.transportContext.getBufferCache().getBuffer();
        try {
            NdrBuffer buf = encodeMessage(msg, out);
            int off = sendFragments(msg, out, buf);

            // last fragment gets written (possibly) using transact/call semantics
            int have = doSendReceiveFragment(out, off, msg.length, inB);

            if ( have != 0 ) {
                NdrBuffer hdrBuf = new NdrBuffer(inB, 0);
                setupReceivedFragment(hdrBuf);
                hdrBuf.setIndex(0);
                msg.decode_header(hdrBuf);
            }

            NdrBuffer msgBuf;
            if ( have != 0 && !msg.isFlagSet(DCERPC_LAST_FRAG) ) {
                msgBuf = new NdrBuffer(receiveMoreFragments(msg, inB), 0);
            }
            else {
                msgBuf = new NdrBuffer(inB, 0);
            }
            msg.decode(msgBuf);
        }
        finally {
            this.transportContext.getBufferCache().releaseBuffer(inB);
            this.transportContext.getBufferCache().releaseBuffer(out);
        }

        DcerpcException de;
        if ( ( de = msg.getResult() ) != null ) {
            throw de;
        }
    }


    /**
     * @param msg
     * @param out
     * @param buf
     * @param off
     * @param tot
     * @return
     * @throws IOException
     */
    private int sendFragments ( DcerpcMessage msg, byte[] out, NdrBuffer buf ) throws IOException {
        int off = 0;
        int headerLength = 24;
        int trailerLength = 0;
        int sec_trailer_len = 0;
        int max_auth_pad_len = 0;
        if (msg.auth_len > 0) {
            /*
                The sec_trailer structure MUST be 4-byte aligned with respect to the beginning of the PDU.
                Padding octets MUST be used to align the sec_trailer structure if its natural beginning
                is not already 4-byte aligned.
             */
            // See https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/rpcrt.py
            /*
                pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
                if pad != 0:
                    rpc_packet['pduData'] += b'\xBB'*pad
                    sec_trailer['auth_pad_len']=pad
             */
            sec_trailer_len = 8;
            max_auth_pad_len = 4;
            int body_len = buf.getLength() - headerLength - sec_trailer_len - msg.auth_len;
            // int auth_pad_len = ? max 4;
            trailerLength = sec_trailer_len + msg.auth_len;
        }
        int headerAndTrailerLength = headerLength + trailerLength;
        int tot = buf.getLength() - headerAndTrailerLength;
        int headerAndMaxTrailerLength = headerAndTrailerLength + max_auth_pad_len;
        while ( off < tot ) {
            int fragSize = tot - off;
            if ( ( headerAndMaxTrailerLength + fragSize ) > this.max_xmit ) {
                // need fragmentation
                msg.flags &= ~DCERPC_LAST_FRAG;
                fragSize = this.max_xmit - headerAndMaxTrailerLength;
            }
            else {
                msg.flags |= DCERPC_LAST_FRAG;
                msg.alloc_hint = fragSize;
            }

            int headerAndMessageLength = headerLength + fragSize;
            int auth_pad_len = 0;
            if (msg.auth_len > 0) {
                auth_pad_len = (4 - (headerAndMessageLength % 4)) % 4;
            }
            trailerLength = auth_pad_len + sec_trailer_len + msg.auth_len;

            msg.length = headerLength + fragSize + trailerLength;

            if ( off > 0 ) {
                msg.flags &= ~DCERPC_FIRST_FRAG;
            }

            NdrBuffer fragBuf = buf;
            if ( ( msg.flags & ( DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG ) ) != ( DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG ) ) {
                fragBuf = new NdrBuffer(new byte[msg.length], 0);
                msg.encode_header(fragBuf);
                fragBuf.enc_ndr_long(msg.alloc_hint);
                fragBuf.enc_ndr_short(0); /* context id */
                fragBuf.enc_ndr_short(msg.getOpnum());

                System.arraycopy(buf.getBuffer(), headerLength + off, fragBuf.getBuffer(), fragBuf.getIndex(), fragSize);
                fragBuf.advance(fragSize);

                if (msg.auth_len > 0) {
                /*
                    For request and response PDUs, where the request and response PDUs are part of a fragmented request
                    or response and authentication is requested (nonzero auth_length),
                    the sec_trailer structure MUST be present in every fragment of the request or response.
                 */
                /*
                    The sec_trailer structure MUST be 4-byte aligned with respect to the beginning of the PDU.
                    Padding octets MUST be used to align the sec_trailer structure if its natural beginning
                    is not already 4-byte aligned.
                 */
                    fragBuf.advance(auth_pad_len);
                    msg.set_auth_pad_len(auth_pad_len);
                    msg.encode_sec_trailer(fragBuf);
                    msg.encode_auth(fragBuf);
                }
            }

            if ( ( msg.flags & DCERPC_LAST_FRAG ) != DCERPC_LAST_FRAG ) {
                // all fragment but the last get written using read/write semantics
                doSendFragment(fragBuf.getBuffer(), 0, msg.length);
                off += fragSize;
            } else if ( ( msg.flags & DCERPC_FIRST_FRAG ) != DCERPC_FIRST_FRAG ) {
                buf.start = off;
                buf.reset();
                msg.encode_header(buf);
                buf.enc_ndr_long(msg.alloc_hint);
                buf.enc_ndr_short(0); /* context id */
                buf.enc_ndr_short(msg.getOpnum());

                System.arraycopy(fragBuf.getBuffer(), headerLength, buf.getBuffer(), buf.getIndex(), fragSize);
                buf.advance(fragSize);

                if (msg.auth_len > 0) {
                    buf.advance(auth_pad_len);
                    msg.set_auth_pad_len(auth_pad_len);
                    msg.encode_sec_trailer(buf);
                    msg.encode_auth(buf);
                }

                return off;
            } else {
                return off;
            }
        }
        throw new IOException();
    }


    /**
     * @param msg
     * @param in
     * @param off
     * @param isDirect
     * @return
     * @throws IOException
     * @throws DcerpcException
     * @throws NdrException
     */
    private byte[] receiveMoreFragments ( DcerpcMessage msg, byte[] in ) throws IOException, DcerpcException, NdrException {
        int headerLength = 24;
        int sec_trailer_len = 0;
        int auth_pad_len = 0;
        int off = msg.ptype == 2 ? msg.length : headerLength;
        byte[] fragBytes = new byte[this.max_recv];
        NdrBuffer fragBuf = new NdrBuffer(fragBytes, 0);
        while ( !msg.isFlagSet(DCERPC_LAST_FRAG) ) {
            int frag_len = doReceiveFragment(fragBytes);
            setupReceivedFragment(fragBuf);
            fragBuf.reset();
            msg.decode_header(fragBuf);
            int bodyStart = fragBuf.getIndex();
            if (msg.auth_len > 0) {
                /*
                    The sec_trailer structure MUST be 4-byte aligned with respect to the beginning of the PDU.
                    Padding octets MUST be used to align the sec_trailer structure if its natural beginning
                    is not already 4-byte aligned.
                 */
                // See https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/rpcrt.py
                /*
                    pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
                    if pad != 0:
                        rpc_packet['pduData'] += b'\xBB'*pad
                        sec_trailer['auth_pad_len']=pad
                 */
                sec_trailer_len = 8;
                // auth_pad_length (1 byte):
                /*
                    The beginning of the sec_trailer structure for each PDU MUST be calculated to start
                    from offset (frag_length – auth_length – 8) from the beginning of the PDU.
                 */
                int auth_type_len = 1;
                int auth_level_len = 1;
                fragBuf.setIndex(msg.length - sec_trailer_len - msg.auth_len + auth_type_len + auth_level_len);
                auth_pad_len = fragBuf.dec_ndr_small();
                fragBuf.setIndex(bodyStart);
            }

            int stub_frag_len;
            if (msg.isFlagSet(DCERPC_LAST_FRAG) ) {
                stub_frag_len = msg.length - headerLength;
            } else {
                stub_frag_len = msg.length - headerLength - auth_pad_len - sec_trailer_len - msg.auth_len;
            }

            if ( ( off + stub_frag_len ) > in.length ) {
                // shouldn't happen if alloc_hint is correct or greater
                byte[] tmp = new byte[off + stub_frag_len];
                System.arraycopy(in, 0, tmp, 0, off);
                in = tmp;
            }
            System.arraycopy(fragBytes, headerLength, in, off, stub_frag_len);
            off += stub_frag_len;
            if (msg.isFlagSet(DCERPC_LAST_FRAG) ) {
                // fix the total length:
                msg.length = off;
                NdrBuffer ndrBuffer = new NdrBuffer(in, 0);
                ndrBuffer.setIndex(8);
                ndrBuffer.enc_ndr_short(off);
            }
        }
        return in;
    }


    /**
     * @param fbuf
     * @throws DcerpcException
     */
    private void setupReceivedFragment ( NdrBuffer fbuf ) throws DcerpcException, NdrException {
        fbuf.reset();
        fbuf.setIndex(8);
        fbuf.setLength(fbuf.dec_ndr_short());

        if ( this.securityProvider != null ) {
            this.securityProvider.unwrap(fbuf);
        }
    }


    /**
     * @param msg
     * @param out
     * @return
     * @throws NdrException
     * @throws DcerpcException
     */
    private NdrBuffer encodeMessage ( DcerpcMessage msg, byte[] out ) throws NdrException, DcerpcException {
        NdrBuffer buf = new NdrBuffer(out, 0);

        msg.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        msg.call_id = call_id.incrementAndGet();

        msg.encode(buf);

        if ( this.securityProvider != null ) {
            buf.setIndex(0);
            this.securityProvider.wrap(buf);
        }
        return buf;
    }


    /**
     *
     * @param securityProvider
     */
    public void setDcerpcSecurityProvider ( DcerpcSecurityProvider securityProvider ) {
        this.securityProvider = securityProvider;
    }


    /**
     *
     * @return the server connected to
     */
    public abstract String getServer ();


    /**
     * @return the server resolved by DFS
     */
    public abstract String getServerWithDfs ();


    /**
     * @return the transport context used
     */
    public abstract CIFSContext getTransportContext ();


    /**
     *
     * @return session key of the underlying smb session
     * @throws CIFSException
     */
    public abstract byte[] getSessionKey () throws CIFSException;


    @Override
    public String toString () {
        return this.binding.toString();
    }


    protected abstract void doSendFragment ( byte[] buf, int off, int length ) throws IOException;


    protected abstract int doReceiveFragment ( byte[] buf ) throws IOException;


    protected abstract int doSendReceiveFragment ( byte[] out, int off, int length, byte[] inB ) throws IOException;


    @Override
    public void close () throws IOException {
        this.state = 0;
    }

}
