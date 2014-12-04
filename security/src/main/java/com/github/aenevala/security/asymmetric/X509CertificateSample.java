package com.github.aenevala.security.asymmetric;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509CertificateSample {
	
	public static void main(String[] args) throws Exception {
		KeyPair alice = SecurityUtils.createKeyPair("ECDSA");
		X509Certificate aliceCert = selfSign("Alice", alice);
		
		// Alice is trusted
		KeyPair bob = SecurityUtils.createKeyPair("ECDSA");
		X509Certificate bobCert = SecurityUtils.sign("Bob", bob.getPublic(), aliceCert, alice.getPrivate());
		System.out.println(aliceCert);
		System.out.println(bobCert);
	}
	
	public static X509Certificate selfSign(String commonName, KeyPair kp) throws Exception {
		X500Name subject = new X500Name("cn="+commonName);
		BigInteger serial = new BigInteger(1024, new SecureRandom());
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, new Date(), SecurityUtils.addYear(), subject, kp.getPublic());
		X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()));
		return new JcaX509CertificateConverter().getCertificate(holder);
	}

}
