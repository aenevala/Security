package com.github.aenevala.security.asymmetric.person;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Person class that uses Elliptic Curve Diffie Hellman key agreement. Sending a
 * message is using ephmeral key pair for each message. Only receiver's static
 * key is needed to be known in advance.
 */
public class SecretECDHPerson {

	private KeyPair kp;
	private String name;
	private KeyAgreement ka;
	private KeyPairGenerator kpg;

	/**
	 * @param name
	 *            Person's name.
	 * @throws Exception
	 */
	public SecretECDHPerson(String name) throws Exception {
		this.name = name;

		kpg = KeyPairGenerator.getInstance("EC", "BC");
		kp = kpg.generateKeyPair();
		ka = KeyAgreement
				.getInstance(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme
						.getId());
	}

	/**
	 * Process the received message.
	 * 
	 * @param from
	 *            the sender
	 * @param encrypted
	 *            encrypted message
	 * @param publicKey
	 *            ephmeral public key used in key agreement
	 * @throws Exception
	 *             if something goes wrong
	 */
	public void receiveMessage(SecretECDHPerson from, byte[] encrypted,
			PublicKey publicKey) throws Exception {
		ka.init(kp.getPrivate());
		ka.doPhase(publicKey, true);
		SecretKey key = ka.generateSecret("AES");

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] decrypted = cipher.doFinal(encrypted);
		String message = new String(decrypted);
		System.out.println(name + " received from " + from.getName() + " "
				+ message);

	}

	/**
	 * @return person's name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return static public key
	 */
	public PublicKey getPublic() {
		return kp.getPublic();
	}

	/**
	 * Sends encrypted message.
	 * 
	 * @param to
	 *            receiver
	 * @param message
	 *            message to be sent
	 * @throws Exception
	 *             if sending fails
	 */
	public void sendMessage(SecretECDHPerson to, String message)
			throws Exception {
		System.out.println(name + " sends message to " + to.getName());
		KeyPair ephmeralKeyPair = kpg.generateKeyPair();
		ka.init(ephmeralKeyPair.getPrivate());
		ka.doPhase(to.getPublic(), true);
		SecretKey key = ka.generateSecret("AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = cipher.doFinal(message.getBytes());
		System.out.println("Encrypted: " + Hex.toHexString(encrypted));
		to.receiveMessage(this, encrypted, ephmeralKeyPair.getPublic());

	}
}
