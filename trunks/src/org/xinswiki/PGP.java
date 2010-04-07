package org.xinswiki;

import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.RSAKeyPair;

public class PGP {
    public static String sign(RSAKeyPair senderKeyPair,byte[] data) {
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
    
}
