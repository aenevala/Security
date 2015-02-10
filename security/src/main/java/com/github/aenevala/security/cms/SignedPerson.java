package com.github.aenevala.security.cms;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import sun.misc.HexDumpEncoder;

import com.github.aenevala.security.asymmetric.SecurityUtils;

public class SignedPerson {

	private KeyPair kp;
	private X509Certificate cert;
	private CMSSignedDataGenerator generator;
	private String name;
	private CertStore store;
	


	public SignedPerson(String name) throws Exception {
		this.name = name;
		kp = SecurityUtils.createKeyPair("ECDSA");
		cert = SecurityUtils.selfSign(name, kp);
		byte[] subjectKeyIdentifier = new JcaX509ExtensionUtils()
				.createSubjectKeyIdentifier(cert.getPublicKey())
				.getKeyIdentifier();

		generator = new CMSSignedDataGenerator();
		generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().build()).build(
				new JcaContentSignerBuilder("SHA256withECDSA").build(kp
						.getPrivate()), subjectKeyIdentifier));

	}
	
	public void trust(SignedPerson person) throws Exception {
		store = new JcaCertStoreBuilder().addCertificate(new JcaX509CertificateHolder(person.getCertificate())).build();
	}

	public X509Certificate getCertificate() {
		return cert;
	}

	public void send(SignedPerson person, String message) throws CMSException,
			IOException {
		CMSProcessableByteArray msg = new CMSProcessableByteArray(
				message.getBytes());
		CMSSignedData signed = generator.generate(msg, true);
		System.out.println("Sending signed data to "+person.name);
		
		System.out.println(new HexDumpEncoder().encode(signed.getEncoded()));
		System.out.println(ASN1Dump.dumpAsString(signed.toASN1Structure(), true));
		person.receive(this, signed.getEncoded());

	}

	public void receive(SignedPerson person, byte[] message) throws CMSException {
		//X509Certificate senderCert = person.getCertificate();
		//System.out.println("Received message from "+person.name);
		
		X509CertSelector selector =  new X509CertSelector();
		selector.setCertificate(person.getCertificate());
		Collection<? extends Certificate> certificates;
		try {
			certificates = store.getCertificates(selector);
			if (certificates.isEmpty()) {
				System.out.println("Not trusting person though claiming to be "+person.name);
				return;
			}

		} catch (CertStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		byte[] subjectKeyIdentifier;
		try {
			subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(person.cert.getPublicKey()).getKeyIdentifier();
			CMSSignedData signedData = new CMSSignedData(message);
			SignerInformation signer = signedData.getSignerInfos().get(new SignerId(subjectKeyIdentifier));
			if (signer != null) {
				boolean valid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(person.cert));
				System.out.println("Received message signature verified: "+valid);
				System.out.println("Received message: "+new String((byte[])signedData.getSignedContent().getContent()));
			} else {
				System.out.println("Sender's certificate doesn't match with the message");
			}

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
