package com.github.aenevala.security.asymmetric;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SecurityUtils {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	public static KeyPair createKeyPair(String algorithm) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
		return kpg.generateKeyPair();
	}
	
	public static X509Certificate selfSign(String commonName, KeyPair kp) throws Exception {
		X500Name subject = new X500Name("cn="+commonName);
		BigInteger serial = new BigInteger(1024, new SecureRandom());
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, new Date(), addYear(), subject, kp.getPublic());
		X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()));
		return new JcaX509CertificateConverter().getCertificate(holder);
	}
	
	public static X509Certificate sign(String commonName, PublicKey publicKey, X509Certificate issuer, PrivateKey issueKey) throws Exception {
		X500Name subject = new X500Name("cn="+commonName);
		BigInteger serial = new BigInteger(1024, new SecureRandom());
		X500Name issuerName = new JcaX500NameUtil().getIssuer(issuer);
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, new Date(), addYear(), subject, publicKey);
		X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issueKey));
		return new JcaX509CertificateConverter().getCertificate(holder);
	}
	
	public static Date addYear() {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.YEAR, 1);
		return cal.getTime();
	}
	


}
