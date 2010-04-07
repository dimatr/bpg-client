package org.xinswiki;

import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.PKCS1SignatureVerifier;
import net.rim.device.api.crypto.RSAKeyPair;
import net.rim.device.api.crypto.RSAPublicKey;

public class PGP {
    public static String signPGP(RSAKeyPair senderKeyPair,byte[] data) {
		try {
			byte[] signature = Crypto.sign( senderKeyPair.getRSAPrivateKey(), data );
	        String str_sign=new String(Utils.encode(signature));
	        return str_sign;
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
    public static boolean verifyPGP(RSAKeyPair senderKeyPair,byte[] data, String str_sign) {
    	byte[] signature = Utils.decode(str_sign).getBytes();
    	try {
			return Crypto.verify(senderKeyPair.getRSAPublicKey(), data, signature);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
    }
}
