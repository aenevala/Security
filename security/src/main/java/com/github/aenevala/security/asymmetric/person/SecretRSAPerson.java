package com.github.aenevala.security.asymmetric.person;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Hex;

/**
 * Secret person that uses RSA key pairs for encryption and decryption.
 */
public class SecretRSAPerson {
	
	private static final String ALGORITHM = "RSA";
	private KeyPair kp;
	private String name;
	private Cipher cipher;
	
	/**
	 * @param name person's name
	 * @throws Exception if security can't be established
	 */
	public SecretRSAPerson(String name) throws Exception {
		this.name = name;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		kp = kpg.generateKeyPair();
		cipher = Cipher.getInstance(ALGORITHM);
	}
	
	/**
	 * @return public key of the person
	 */
	public PublicKey getPublicKey() {
		return kp.getPublic();
	}
	
	/**
	 * Decrypts received message.
	 * @param encryptedMessage encrypted message with person's public key
	 * @throws Exception if decryption fails
	 */
	public void receiveMessage(byte[] encryptedMessage) throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
		byte[] decrypted = cipher.doFinal(encryptedMessage);
		String message = new String(decrypted);
		System.out.println(name + " received: "+message);
	}
	
	/**
	 * Encrypts message with receiver's public key and sends message to receiver.
	 * @param to receiver
	 * @param message message to be sent
	 * @throws Exception if encryption fails
	 */
	public void sendMessage(SecretRSAPerson to, String message) throws Exception {
		System.out.println(name + " sends message to "+to.getName());
		cipher.init(Cipher.ENCRYPT_MODE, to.getPublicKey());
		byte[] encrypted = cipher.doFinal(message.getBytes());
		System.out.println("Encrypted message: "+Hex.toHexString(encrypted));
		to.receiveMessage(encrypted);
	}
	
	/**
	 * @return person's name
	 */
	public String getName() {
		return name;
	}

}