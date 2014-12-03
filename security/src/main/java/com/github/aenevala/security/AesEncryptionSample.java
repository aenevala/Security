package com.github.aenevala.security;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Sample for showing how to encrypt and decrypt using AES key.
 */
public class AesEncryptionSample {


	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// Generate AES128 key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey key = keyGenerator.generateKey();
		System.out.println(key.getAlgorithm()+key.getEncoded().length * 8);
		System.out.println("Key: "+Hex.toHexString(key.getEncoded()));

		// This is our secret		
		String plainText = "GSNext";
		
		// Let's encrypt it
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(plainText.getBytes());
		System.out.println("Encrypted: "+Hex.toHexString(cipherText));
		
		// Let's decrypt it back
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(cipher.getIV()));
	
		byte[] decrypted = cipher.doFinal(cipherText);
		System.out.println("Decrypted: "+new String(decrypted));
		
	}

}
