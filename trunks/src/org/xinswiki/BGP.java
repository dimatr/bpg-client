package org.xinswiki;

import java.io.IOException;

import net.rim.blackberry.api.mail.Message;
import net.rim.blackberry.api.mail.MessagingException;
import net.rim.blackberry.api.mail.NoSuchServiceException;
import net.rim.blackberry.api.mail.SendListener;
import net.rim.blackberry.api.mail.Session;
import net.rim.blackberry.api.mail.Store;
import net.rim.device.api.ui.*;
import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.RSACryptoSystem;
import net.rim.device.api.crypto.RSAKeyPair;

public class BGP extends UiApplication implements SendListener{

	public BGP() {
		// TODO Auto-generated constructor stub
		try 
		{
			Store store = Session.waitForDefaultSession().getStore();
			store.addSendListener(this);
		}
		catch (NoSuchServiceException e) 
		{
		   System.out.println(e.toString());
		}
	}
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BGP theApp = new BGP();
		theApp.enterEventDispatcher();
	}

	public boolean sendMessage(Message message) {
		// TODO Auto-generated method stub
		String orgMsg = new String(message.getBodyText());
        byte[] data = orgMsg.getBytes();
        try {
	        // Create the RSAKeyPair that will be used for all of these operations.
	        RSAKeyPair senderKeyPair = new RSAKeyPair( new RSACryptoSystem( 1024 ));
	        RSAKeyPair recipientKeyPair = new RSAKeyPair( new RSACryptoSystem( 1024 ));
	        
	        // First, we want to sign the data with the sender's private key.
	        //byte[] signature = Crypto.sign( senderKeyPair.getRSAPrivateKey(), data );
	        String str_sign=PGP.signPGP(senderKeyPair.getRSAPrivateKey(), data);
	        boolean verfied = PGP.verifyPGP(senderKeyPair.getRSAPublicKey(),data,str_sign);
	        
	        // Next, we want to encrypt the data for the recipient.
	        byte[] ciphertext=PGP.encryptPGP(recipientKeyPair.getRSAPublicKey(), data);
	        
	        ///////////////////////////////////////////////////////////////////////////
	        /// At this point pretend that the data has been sent to the recipient  ///
	        /// and the recipient is going to decrypt and verify the data.          ///
	        ///////////////////////////////////////////////////////////////////////////

	        // Decrypt the data.
	        byte[] plaintext = PGP.decryptPGP( recipientKeyPair.getRSAPrivateKey(), ciphertext );
	        String str_plain = new String(plaintext);
	        String str_Armored_MSG= new String("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1\n\n");
	        str_Armored_MSG=str_Armored_MSG.concat(orgMsg);
	        str_Armored_MSG=str_Armored_MSG.concat("\n-----BEGIN PGP SIGNATURE-----\nVersion: BGP v.0.0.1(xinswiki.org)\n\n");
	        str_Armored_MSG=str_Armored_MSG.concat(str_sign);
	        str_Armored_MSG=str_Armored_MSG.concat("\n-----END PGP SIGNATURE-----\n");
	        if (verfied)
	        {
		        str_Armored_MSG=str_Armored_MSG.concat("-----PGP SIGNATURE VERIFIED-----\n");
	        }
	        else
	        {
		        str_Armored_MSG=str_Armored_MSG.concat("-----PGP SIGNATURE NOT VERIFIED-----\n");
	        }
	        str_Armored_MSG=str_Armored_MSG.concat("-----BEGIN PGP Decypted plaintext-----\n");
	        str_Armored_MSG=str_Armored_MSG.concat(str_plain);
	        str_Armored_MSG=str_Armored_MSG.concat("\n-----END PGP Decypted plaintext-----\n");
	        
	        System.out.println(str_Armored_MSG);
	        try {
	        	message.setContent(str_Armored_MSG);
	    		return true;
	        	}
	        catch(MessagingException e){
	            System.out.println( "An unexpected exception occurred.  Please verify your work or ask for help." );
	        }
        } catch( CryptoException e ) {
            System.out.println( "An unexpected exception occurred.  Please verify your work or ask for help." );
        }
		return false;
	}
}
