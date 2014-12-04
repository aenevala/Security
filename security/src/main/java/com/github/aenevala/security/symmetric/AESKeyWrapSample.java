package com.github.aenevala.security.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESKeyWrapSample {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();
		SecretKey keyEncryptionKey = kg.generateKey();
		System.out.println("Key: "+Hex.toHexString(key.getEncoded()));
		Cipher cipher = Cipher.getInstance("AESWrap");
		// Wrap
		cipher.init(Cipher.WRAP_MODE, keyEncryptionKey);
		byte[] wrapped = cipher.wrap(key);
		System.out.println("Wrapped: "+Hex.toHexString(wrapped));
		// Unwrap
		cipher.init(Cipher.UNWRAP_MODE, keyEncryptionKey);
		key = (SecretKey) cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
		System.out.println("Unwrapped: "+Hex.toHexString(key.getEncoded()));
		
		
	}
}
