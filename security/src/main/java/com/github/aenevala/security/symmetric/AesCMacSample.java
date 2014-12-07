package com.github.aenevala.security.symmetric;

import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Basic Mac calculation sample using AESCMac and AESGMac algorithms.
 * @see AesCMacSample Advanced GMAC usage
 */
public class AesCMacSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		SecretKey key = KeyGenerator.getInstance("AES").generateKey();
		Mac cmac = Mac.getInstance("AESCMac");
		cmac.init(key);
		String text = "Hello World!";
		byte[] cmacBytes = cmac.doFinal(text.getBytes());
		System.out.println("CMAC: "+Hex.toHexString(cmacBytes));
		
		Mac gmac = Mac.getInstance("AESGMac");
		gmac.init(key, new IvParameterSpec(new byte[12]));
		byte[] gmacBytes = gmac.doFinal(text.getBytes());
		System.out.println("GMAC: "+Hex.toHexString(gmacBytes));
		
	}

}
