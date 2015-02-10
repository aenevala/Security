package com.github.aenevala.security.cms;


public class SignedDataSample {

	public static void main(String[] args) throws Exception {
		CMSPerson alice = new CMSPerson("Alice");
		CMSPerson bob = new CMSPerson("Bob");
		bob.trust(alice);
		
		alice.sendSigned(bob, "Hi Bob!");
		
		CMSPerson carol = new CMSPerson("Alice");
		carol.sendSigned(bob, "Greetings from Alice");
		
		
	}
}
