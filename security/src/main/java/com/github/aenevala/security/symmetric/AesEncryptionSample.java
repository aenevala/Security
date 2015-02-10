package com.github.aenevala.security.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Sample for showing how to encrypt and decrypt using AES key.
 */
public class AesEncryptionSample {

	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// Generate AES128 key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey key = keyGenerator.generateKey();
		System.out.println(key.getAlgorithm() + key.getEncoded().length * 8);
		System.out.println("Key: " + Hex.toHexString(key.getEncoded()));

		// This is our secret
		String plainText = "GSNext";
	
		// Do twice to see the if encrypted bytes get changed
		doCryptography(key, plainText, ALGORITHM);
		doCryptography(key, plainText, ALGORITHM);

	}

	private static void doCryptography(SecretKey key, String plainText, String algorithm)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Let's encrypt it
		Cipher cipher = Cipher.getInstance(algorithm, "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(plainText.getBytes());
		System.out.println("Encrypted: " + Hex.toHexString(cipherText));

		// Let's decrypt it back
		if (cipher.getIV() != null) {
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(cipher.getIV()));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, key);
		}

		byte[] decrypted = cipher.doFinal(cipherText);
		System.out.println("Decrypted: " + new String(decrypted));
	}

}
