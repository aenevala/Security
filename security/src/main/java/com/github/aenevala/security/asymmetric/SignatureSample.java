package com.github.aenevala.security.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * This sample shows how to use Signatures with asymmetric key pairs (ECDSA).
 */
public class SignatureSample {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		
		// Use brainpool P256r1 named curve
		kpg.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers.brainpoolP256r1.getId()));
		KeyPair kp = kpg.generateKeyPair();
		
		String plainText = "Hello world!";
		
		// Sign
		// If RSA key pairs are used then signature algorithm would be SHA256withRSA
		Signature signature = Signature.getInstance(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "BC");
		signature.initSign(kp.getPrivate());
		signature.update(plainText.getBytes());
		byte[] signatureBytes = signature.sign();
		
		System.out.println("Signature: "+Hex.toHexString(signatureBytes));
		// Verify
		signature.initVerify(kp.getPublic());
		signature.update(plainText.getBytes());
		
		//Should throw an exception if verification fails
		signature.verify(signatureBytes);
		
		
	}
}
