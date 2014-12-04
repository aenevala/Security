package com.github.aenevala.security.symmetric;

import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AesCMacSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		SecretKey key = KeyGenerator.getInstance("AES").generateKey();
		Mac mac = Mac.getInstance("AESCMac");
		mac.init(key);
		String text = "Hello World!";
		byte[] hash = mac.doFinal(text.getBytes());
		System.out.println("MAC: "+Hex.toHexString(hash));
		
	}

}
