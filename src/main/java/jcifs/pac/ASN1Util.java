/*
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
package jcifs.pac;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DLSequence;


/**
 *
 *
 */
public final class ASN1Util {

    private ASN1Util () {}


    /**
     *
     * @param type
     * @param object
     * @return object cast to type
     * @throws PACDecodingException
     */
    public static <T> T as ( Class<T> type, Object object ) throws PACDecodingException {
        if ( !type.isInstance(object) ) {
            throw new PACDecodingException("Incompatible object types " + type + " " + object.getClass());
        }

        return type.cast(object);
    }


    /**
     *
     * @param type
     * @param enumeration
     * @return next element from enumeration cast to type
     * @throws PACDecodingException
     */
    public static <T extends Object> T as ( Class<T> type, Enumeration<?> enumeration ) throws PACDecodingException {
        return as(type, enumeration.nextElement());
    }


    /**
     *
     * @param type
     * @param stream
     * @return next object from stream cast to type
     * @throws PACDecodingException
     * @throws IOException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1InputStream stream ) throws PACDecodingException, IOException {
        return as(type, stream.readObject());
    }


    /**
     *
     * @param type
     * @param tagged
     * @return tagged object contents cast to type
     * @throws PACDecodingException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, ASN1TaggedObject tagged ) throws PACDecodingException {
        return as(type, tagged.getBaseObject());
    }


    /**
     *
     * @param type
     * @param sequence
     * @param index
     * @return sequence element cast to type
     * @throws PACDecodingException
     */
    public static <T extends ASN1Primitive> T as ( Class<T> type, DLSequence sequence, int index ) throws PACDecodingException {
        return as(type, sequence.getObjectAt(index));
    }

    /**
     * Additional plumbing required because BouncyCastle removed {@code DERApplicationSpecific} since version 1.75.
     *
     * @param derApplicationSpecific
     * @return
     * @throws PACDecodingException
     * @since 2.11.0
     */
    public static byte[] getDERApplicationSpecificContents(byte[] derApplicationSpecific) throws PACDecodingException {
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(derApplicationSpecific));
        return getDERApplicationSpecificContents(stream);
    }

    /**
     * Additional plumbing required because BouncyCastle removed {@code DERApplicationSpecific} since version 1.75.
     *
     * @param derApplicationSpecific
     * @return
     * @throws PACDecodingException
     * @since 2.11.0
     */
    public static byte[] getDERApplicationSpecificContents(ASN1InputStream stream) throws PACDecodingException {
        ASN1TaggedObject derToken;
        try {
            derToken = ASN1Util.as(ASN1TaggedObject.class, stream);
            if (derToken.getTagClass() != BERTags.APPLICATION) {
                throw new PACDecodingException("Malformed DERApplicationSpecific");
            }
            stream.close();
        } catch (IOException e) {
            throw new PACDecodingException("Malformed DERApplicationSpecific", e);
        }

        return getContents(derToken);
    }

    /**
     * Additional plumbing required because BouncyCastle removed {@code DERApplicationSpecific} since version 1.75.
     *
     * @since 2.11.0
     */
    public static byte[] getContents(ASN1TaggedObject asn1TaggedObject) {
        byte[] contents;
        try {
            // byte[] ASN1TaggedObject.getContents()
            Method getContentsMethod = ASN1TaggedObject.class.getDeclaredMethod("getContents");
            getContentsMethod.setAccessible(true);
            contents = (byte[]) getContentsMethod.invoke(asn1TaggedObject);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return contents;
    }
}
