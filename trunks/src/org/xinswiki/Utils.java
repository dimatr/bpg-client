package org.xinswiki;

public class Utils {

    /**
     * Encodes a String into a base 64 String. The resulting encoding is chunked at 76 bytes.
     * <p>
     * @param s String to encode.
     * @return encoded string.
     *
     */
    public static String encode(String s) {
        byte[] sBytes =  s.getBytes();
        sBytes = encode(sBytes);
        s = new String(sBytes);
        return s;
    }

    /**
     * Decodes a base 64 String into a String.
     * <p>
     * @param s String to decode.
     * @return encoded string.
     * @throws java.lang.IllegalArgumentException thrown if the given byte array was not valid com.sun.syndication.io.impl.Base64 encoding.
     *
     */
    public static String decode(String s) throws IllegalArgumentException {
        s = s.replace('\n','\u0000');
        s = s.replace('\r','\u0000');
        byte[] sBytes = s.getBytes();
        sBytes = decode(sBytes);
        s = new String(sBytes);
        return s;
    }


    private static final byte[] ALPHASET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".getBytes();

    private static final int I6O2 = 255 - 3;
    private static final int O6I2 = 3;
    private static final int I4O4 = 255 - 15;
    private static final int O4I4 = 15;
    private static final int I2O6 = 255 - 63;
    private static final int O2I6 = 63;

    /**
     * Encodes a byte array into a base 64 byte array.
     * <p>
     * @param dData byte array to encode.
     * @return encoded byte array.
     *
     */
    public static byte[] encode(byte[] dData) {
        if (dData==null) {
            throw new IllegalArgumentException("Cannot encode null");
        }
        byte[] eData = new byte[((dData.length+2)/3)*4];

        int eIndex = 0;
        for (int i = 0; i<dData.length; i += 3) {
            int d1;
            int d2=0;
            int d3=0;
            int e1;
            int e2;
            int e3;
            int e4;
            int pad=0;

            d1 = dData[i];
            if ((i+1)<dData.length) {
                d2 = dData[i+1];
                if ((i+2)<dData.length) {
                    d3 = dData[i+2];
                }
                else {
                    pad =1;
                }
            }
            else {
                pad =2;
            }

            e1 = ALPHASET[(d1&I6O2)>>2];
            e2 = ALPHASET[(d1&O6I2)<<4 | (d2&I4O4)>>4];
            e3 = ALPHASET[(d2&O4I4)<<2 | (d3&I2O6)>>6];
            e4 = ALPHASET[(d3&O2I6)];

            eData[eIndex++] = (byte)e1;
            eData[eIndex++] = (byte)e2;
            eData[eIndex++] = (pad<2) ?(byte)e3 : (byte)'=';
            eData[eIndex++] = (pad<1) ?(byte)e4 : (byte)'=';

        }
        return eData;
    }

    private final static int[] CODES = new int[256];

    static {
        for (int i=0;i<CODES.length;i++) {
            CODES[i] = 64;
        }
        for (int i=0;i<ALPHASET.length;i++) {
            CODES[ALPHASET[i]] = i;
        }
    }

    /**
     * Dencodes a com.sun.syndication.io.impl.Base64 byte array.
     * <p>
     * @param eData byte array to decode.
     * @return decoded byte array.
     * @throws java.lang.IllegalArgumentException thrown if the given byte array was not valid com.sun.syndication.io.impl.Base64 encoding.
     *
     */
    public static byte[] decode(byte[] eData) {
        if (eData==null) {
            throw new IllegalArgumentException("Cannot decode null");
        }
        
        byte[] cleanEData = new byte[eData.length];
        for (int z=0;z<eData.length;z++)
        {
        	cleanEData[z]=eData[z];
        }
        //byte[] cleanEData = (byte[]) eData.clone();
        int cleanELength = 0;
        for (int i=0;i<eData.length;i++) {
            if (eData[i]<256 && CODES[eData[i]]<64) {
                cleanEData[cleanELength++] = eData[i];
            }
        }

        int dLength = (cleanELength/4)*3;
        switch (cleanELength%4) {
            case 3:
                dLength += 2;
                break;
            case 2:
                dLength++;
                break;
        }

        byte[] dData = new byte[dLength];
        int dIndex = 0;
        for (int i = 0; i < eData.length; i += 4) {
            if ((i + 3) > eData.length) {
                throw new IllegalArgumentException("byte array is not a valid com.sun.syndication.io.impl.Base64 encoding");
            }
            int e1 = CODES[cleanEData[i]];
            int e2 = CODES[cleanEData[i+1]];
            int e3 = CODES[cleanEData[i+2]];
            int e4 = CODES[cleanEData[i+3]];
            dData[dIndex++] = (byte) ((e1<<2)|(e2>>4));
            if (dIndex<dData.length) {
                dData[dIndex++] = (byte) ((e2<<4) | (e3>>2));
            }
            if (dIndex<dData.length) {
                dData[dIndex++] = (byte) ((e3<<6) | (e4));
            }
        }
        return dData;
    }
}
