package com.github.aenevala.security.symmetric;

import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESGMacSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();
		
		// Using JCE Cipher API
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[8];
		new Random().nextBytes(iv);
		GCMParameterSpec spec = new GCMParameterSpec(96, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		String plainText = "Hello World!";
		// Use updateAAD method only to get MAC
		cipher.updateAAD(plainText.getBytes());
		byte[] gmac = cipher.doFinal();
		System.out.println(Hex.toHexString(gmac));
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		cipher.updateAAD(plainText.getBytes());
		cipher.doFinal(gmac);
		
		// Using Bouncy castle GMAC API
		GMac gMac = new GMac(new GCMBlockCipher(new AESFastEngine()),96);
		KeyParameter param = new KeyParameter(key.getEncoded());
		gMac.init(new ParametersWithIV(param, iv));
		gMac.update(plainText.getBytes(), 0, plainText.length());
		byte[] output = new byte[gMac.getMacSize()];
		gMac.doFinal(output, 0);
		System.out.println(Hex.toHexString(output));
		
		System.out.println("JCE and BC MACs equal: "+Arrays.equals(gmac, output));
		
		
		
	}

}
 