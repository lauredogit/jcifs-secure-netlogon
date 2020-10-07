/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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


import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrObject;


/**
 *
 */
public abstract class DcerpcMessage extends NdrObject implements DcerpcConstants {

    protected int ptype = -1;
    protected int flags = 0;
    protected int length = 0;
    protected int auth_len = 0;
    protected int call_id = 0;
    protected int alloc_hint = 0;
    protected int result = 0;

    /**
     *
     * @param flag
     * @return whether flag is set
     */
    public boolean isFlagSet ( int flag ) {
        return ( this.flags & flag ) == flag;
    }


    /**
     * Remove flag
     *
     * @param flag
     */
    public void unsetFlag ( int flag ) {
        this.flags &= ~flag;
    }


    /**
     * Set flag
     *
     * @param flag
     */
    public void setFlag ( int flag ) {
        this.flags |= flag;
    }


    /**
     *
     * @return result exception, if the call failed
     */
    public DcerpcException getResult () {
        if ( this.result != 0 )
            return new DcerpcException(this.result);
        return null;
    }

    /**
     * See 12.6.4.9 The request PDU
     *
     * See also https://github.com/SecureAuthCorp/impacket/blob/fe642b24be7aa870251df8a650ba1ac3bb8ef7e4/impacket/dcerpc/v5/rpcrt.py#L651
     */
    protected void encode_header ( NdrBuffer buf ) {
        // ver_major
        buf.enc_ndr_small(5); /* RPC version */
        // ver_minor
        buf.enc_ndr_small(0); /* minor version */
        // type
        buf.enc_ndr_small(this.ptype);
        // flags
        buf.enc_ndr_small(this.flags);
        // representation
        buf.enc_ndr_long(0x00000010); /* Little-endian / ASCII / IEEE */
        // frag_len
        // ('frag_len','<H=self._SIZE+len(auth_data)+(16 if (self["flags"] & 0x80) > 0 else 0)+len(pduData)+len(pad)+len(sec_trailer)'),  # 8
        buf.enc_ndr_short(this.length);
        // auth_len
        buf.enc_ndr_short(this.auth_len); /* length of auth_value */
        // call_id
        buf.enc_ndr_long(this.call_id);
    }

    protected void decode_header ( NdrBuffer buf ) throws NdrException {
        /* RPC major / minor version */
        if ( buf.dec_ndr_small() != 5 || buf.dec_ndr_small() != 0 ) {
            throw new NdrException("DCERPC version not supported");
        }
        this.ptype = buf.dec_ndr_small();
        this.flags = buf.dec_ndr_small();
        if ( buf.dec_ndr_long() != 0x00000010 ) { /* Little-endian / ASCII / IEEE */
            throw new NdrException("Data representation not supported");
        }
        this.length = buf.dec_ndr_short();
        // auth_len
        this.auth_len = buf.dec_ndr_short();
        this.call_id = buf.dec_ndr_long();
    }

    protected void encode_sec_trailer( NdrBuffer buf ) throws NdrException {
    }

    protected void encode_auth( NdrBuffer buf ) throws NdrException {
    }


    @Override
    public void encode ( NdrBuffer buf ) throws NdrException {
        int start = buf.getIndex();
        int alloc_hint_index = 0;

        buf.advance(16); /* momentarily skip header */
        if ( this.ptype == 0 ) { /* Request */
            alloc_hint_index = buf.getIndex();
            buf.enc_ndr_long(0); /* momentarily skip alloc hint */
            buf.enc_ndr_short(0); /* context id */
            buf.enc_ndr_short(getOpnum());
        }

        encode_in(buf);
        if (auth_len > 0) {
            /*
                The sec_trailer structure MUST be 4-byte aligned with respect to the beginning of the PDU.
                Padding octets MUST be used to align the sec_trailer structure if its natural beginning
                is not already 4-byte aligned.
             */
            buf.align(4);
            encode_sec_trailer(buf);
            encode_auth(buf);
        }

        this.length = buf.getIndex() - start;

        if ( this.ptype == 0 ) {
            buf.setIndex(alloc_hint_index);
            this.alloc_hint = this.length - alloc_hint_index;
            buf.enc_ndr_long(this.alloc_hint);
        }

        buf.setIndex(start);
        encode_header(buf);
        buf.setIndex(start + this.length);
    }

    @Override
    public void decode ( NdrBuffer buf ) throws NdrException {
        decode_header(buf);

        if ( this.ptype != 12 && this.ptype != 2 && this.ptype != 3 && this.ptype != 13 )
            throw new NdrException("Unexpected ptype: " + this.ptype);

        if ( this.ptype == 2 || this.ptype == 3 ) { /* Response or Fault */
            this.alloc_hint = buf.dec_ndr_long();
            buf.dec_ndr_short(); /* context id */
            buf.dec_ndr_short(); /* cancel count */
        }
        if ( this.ptype == 3 || this.ptype == 13 ) { /* Fault */
            this.result = buf.dec_ndr_long();
        }
        else { /* Bind_ack or Response */
            decode_out(buf);
        }
    }


    /**
     *
     * @return the operation number
     */
    public abstract int getOpnum ();


    /**
     *
     * @param buf
     * @throws NdrException
     */
    public abstract void encode_in ( NdrBuffer buf ) throws NdrException;


    /**
     *
     * @param buf
     * @throws NdrException
     */
    public abstract void decode_out ( NdrBuffer buf ) throws NdrException;

    public int getPtype() {
        return ptype;
    }

    public void setPtype(int ptype) {
        this.ptype = ptype;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public int get_auth_len() {
        return auth_len;
    }

    public void set_auth_len(int auth_len) {
        this.auth_len = auth_len;
    }

    public int getLength() {
        return length;
    }
}
