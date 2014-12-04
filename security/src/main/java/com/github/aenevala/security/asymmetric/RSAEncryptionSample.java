package com.github.aenevala.security.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.github.aenevala.security.asymmetric.person.SecretRSAPerson;

public class RSAEncryptionSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		SecretRSAPerson alice = new SecretRSAPerson("Alice");
		SecretRSAPerson bob = new SecretRSAPerson("Bob");
		alice.sendMessage(bob, "Hello!");
		bob.sendMessage(alice, "Bye!");
		
	}
	
	
	
	

}
 