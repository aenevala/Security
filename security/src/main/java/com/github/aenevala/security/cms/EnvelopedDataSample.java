package com.github.aenevala.security.cms;


public class EnvelopedDataSample {
	public static void main(String[] args) throws Exception {
		CMSPerson alice = new CMSPerson("Alice");
		CMSPerson bob = new CMSPerson("Bob");
		alice.sendEnveloped(bob, "Hi Bob!");
		bob.sendEnveloped(alice, "Hi Alice!");
	}

}
