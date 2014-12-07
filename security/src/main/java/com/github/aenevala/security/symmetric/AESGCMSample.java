package com.github.aenevala.security.symmetric;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
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
		
		// Encrypt using JCE AES/GCM/NoPadding algorithm
		
		GCMParameterSpec spec = new GCMParameterSpec(128, iv);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		
		String plainText = "Hello World!";
		byte[] encrypted = cipher.doFinal(plainText.getBytes());
		System.out.println(Hex.toHexString(encrypted));
		
		//Comment this out if want to test mac failure
		//encrypted[encrypted.length-1] ^= 1; // change the last byte using byte XOR 1
		
		// Decrypt using Bouncy castle lightweight API
		
		GCMBlockCipher gcmCipher = new GCMBlockCipher(new AESFastEngine());
		gcmCipher.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), 128, iv));
		int outputSize = gcmCipher.getOutputSize(encrypted.length);
		byte[] output = new byte[outputSize];
		gcmCipher.processBytes(encrypted, 0, encrypted.length, null, -1);
		gcmCipher.doFinal(output, 0);
		System.out.println(new String(output));
		
	}
}
