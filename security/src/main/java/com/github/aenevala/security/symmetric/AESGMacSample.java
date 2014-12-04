package com.github.aenevala.security.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESGMacSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();
		
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[8];
		new Random().nextBytes(iv);
		GCMParameterSpec spec = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		String plainText = "Hello World!";
		cipher.updateAAD(plainText.getBytes());
		byte[] gmac = cipher.doFinal();
		System.out.println(Hex.toHexString(gmac));
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		cipher.updateAAD(plainText.getBytes());
		cipher.doFinal(gmac);
		
	}

}
 