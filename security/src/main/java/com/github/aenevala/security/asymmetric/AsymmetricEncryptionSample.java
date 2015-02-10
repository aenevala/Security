package com.github.aenevala.security.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.github.aenevala.security.asymmetric.person.SecretAsymmetricPerson;

public class AsymmetricEncryptionSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		SecretAsymmetricPerson alice = new SecretAsymmetricPerson("Alice", "RSA");
		SecretAsymmetricPerson bob = new SecretAsymmetricPerson("Bob", "RSA");
		alice.sendMessage(bob, "Hello Bob!");
		bob.sendMessage(alice, "Bye Alice!");
		
		SecretAsymmetricPerson carol = new SecretAsymmetricPerson("Carol", "ECIES");
		SecretAsymmetricPerson david = new SecretAsymmetricPerson("David", "ECIES");
		carol.sendMessage(david, "Hi David!");
		
		
	}
	
	
	
	

}
 