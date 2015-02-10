package com.github.aenevala.security.cms;


public class SignedDataSample {

	public static void main(String[] args) throws Exception {
		SignedPerson alice = new SignedPerson("Alice");
		SignedPerson bob = new SignedPerson("Bob");
		bob.trust(alice);
		
		alice.send(bob, "Hi Bob!");
		
		SignedPerson carol = new SignedPerson("Alice");
		carol.send(bob, "Greetings from Alice");
		
		
	}
}
