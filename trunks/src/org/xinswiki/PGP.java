package org.xinswiki;

import java.io.IOException;

import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.PKCS1SignatureVerifier;
import net.rim.device.api.crypto.RSAPrivateKey;
import net.rim.device.api.crypto.RSAPublicKey;

public class PGP {
    public static String signPGP(RSAPrivateKey sendertPrivateKey,byte[] data) {
		try {
			byte[] signature = Crypto.sign(sendertPrivateKey, data );
	        String str_sign=new String(Utils.encode(signature));
	        return str_sign;
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
    public static boolean verifyPGP(RSAPublicKey senderPublicKey,byte[] data, String str_sign) {
    	byte[] signature = Utils.decode(str_sign).getBytes();
    	try {
			return Crypto.verify(senderPublicKey, data, signature);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
    }
    public static byte[] encryptPGP(RSAPublicKey recipientPublicKey, byte[] plaintext){
    	try {
			return Crypto.encrypt(recipientPublicKey, plaintext);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
    public static byte[] decryptPGP(RSAPrivateKey sendertPrivateKey, byte[] ciphertext){
    	try {
			return Crypto.decrypt(sendertPrivateKey, ciphertext);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
}
