package com.github.aenevala.security.asymmetric;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.github.aenevala.security.asymmetric.person.SecretECDHPerson;

/**
 * Secured communication using Elliptic Curve Diffie Hellman Key agreement.
 * See {@link SecretECDHPerson}
 *
 */
public class ECDHKeyAgreementSample {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		SecretECDHPerson alice = new SecretECDHPerson("Alice");
		SecretECDHPerson bob = new SecretECDHPerson("Bob");
		alice.sendMessage(bob, "Hello!");
		bob.sendMessage(alice, "Bye!");
		alice.sendMessage(bob, "Hello!");
		
	}

}
