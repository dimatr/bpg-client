package org.xinswiki;

import java.io.*;

import net.rim.device.api.crypto.*;
import net.rim.device.api.util.*;

public class Crypto {
	

    /**
     * Encrypt the plaintext passed into this method using the public key.  The ciphertext should
     * be returned from the method.
     * @param publicKey an RSAPublicKey that should be used for encrypting the data.
     * @param plaintext the data to be encrypted.
     * @return the ciphertext or encrypted data.
     */
    public static byte[] encrypt( RSAPublicKey publicKey, byte[] plaintext ) throws CryptoException, IOException
    {
        // Create the encryptor engine.
        RSAEncryptorEngine engine = new RSAEncryptorEngine( publicKey );

        // Use the OAEP padding for the encryption.  Note that this
        // defaults to using SHA1.
        OAEPFormatterEngine fengine = new OAEPFormatterEngine( engine );

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        BlockEncryptor encryptor = new BlockEncryptor( fengine, output );

        // Write out the data.
        encryptor.write( plaintext );
        encryptor.close();
        output.close();
        return output.toByteArray();
    }

    /**
     * Decrypt the ciphertext passed into this method using the public key.  The plaintext should
     * be returned from the method.
     * @param privateKey an RSAPrivateKey that should be used for decrypting the data.
     * @param ciphertext the data to be decrypted.
     * @return the plaintext or decrypted data.
     */
    public static byte[] decrypt( RSAPrivateKey privateKey, byte[] ciphertext ) throws CryptoException, IOException
    {
        // Create the decryptor engine.
        RSADecryptorEngine engine = new RSADecryptorEngine( privateKey );

        // Use the OAEP padding.
        OAEPUnformatterEngine uengine = new OAEPUnformatterEngine( engine );

        ByteArrayInputStream input = new ByteArrayInputStream( ciphertext );
        BlockDecryptor decryptor = new BlockDecryptor( uengine, input );

        // Now, read in the data.  Remember that the last 20 bytes represent the SHA1 hash of the decrypted data.
        byte[] temp = new byte[ 100 ];
        DataBuffer buffer = new DataBuffer();

        for( ;; ) {
            int bytesRead = decryptor.read( temp );
            buffer.write( temp, 0, bytesRead );

            if( bytesRead < 100 ) {
                // We ran out of data.
                break;
            }
        }

        return buffer.getArray();
    }

    /**
     * Use the data and the public key to produce a signature that will provide data integrity
     * and data authentication.
     * @param privateKey the public key to use for signing the data.
     * @param data the data to be signed.
     * @return the signature.
     */
    public static byte[] sign( RSAPrivateKey privateKey, byte[] data ) throws CryptoException
    {
        // Create the PKCS1 signature signer.  This is the standard method used
        // to create a signature with an RSA key.  Note that by default this uses
        // a SHA digest.
        PKCS1SignatureSigner signer = new PKCS1SignatureSigner( privateKey );
        signer.update( data );

        byte[] signature = new byte[ signer.getLength() ];
        signer.sign( signature, 0 );

        return signature;
    }

    /**
     * Use the data and the public key to verifying that the signature is correct.
     * @param publicKey the Public Key to use for verification.
     * @param data the data that the signature was created with.
     * @param signature the signature on the data.
     * @return a boolean indicating whether or not the signature is valid.
     */
    public static boolean verify( RSAPublicKey publicKey, byte[] data, byte[] signature ) throws CryptoException
    {
        PKCS1SignatureVerifier verifier = new PKCS1SignatureVerifier( publicKey, signature, 0 );
        verifier.update( data );
        return verifier.verify();
    }
}

