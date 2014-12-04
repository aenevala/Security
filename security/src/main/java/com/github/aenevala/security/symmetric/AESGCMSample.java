package com.github.aenevala.security.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESGCMSample {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();
		byte[] iv = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		GCMParameterSpec spec = new GCMParameterSpec(128, iv);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		
		String plainText = "Hello World!";
		System.out.println(plainText.length());
		byte[] encrypted = cipher.doFinal(plainText.getBytes());
		System.out.println(Hex.toHexString(encrypted));
		System.out.println(encrypted.length);
	}
}
