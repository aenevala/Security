package com.github.aenevala.security.cms;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.asn1.cms.CompressedDataParser;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSCompressedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyAgreeRecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import sun.misc.HexDumpEncoder;

import com.github.aenevala.security.asymmetric.SecurityUtils;

/**
 * Person that can send and receive CMS messages. Person uses Elliptic curve
 * cryptography for CMS messages
 */
public class CMSPerson {

	private KeyPair kp;
	private X509Certificate cert;
	private CMSSignedDataGenerator signedDataGenerator;
	private String name;
	private CertStore store;

	/**
	 * Create new CMS person
	 * 
	 * @param name
	 *            person name
	 * @throws Exception
	 *             if CMS creation fails
	 */
	public CMSPerson(String name) throws Exception {
		this.name = name;
		kp = SecurityUtils.createKeyPair("ECDSA");
		cert = SecurityUtils.selfSign(name, kp);
		byte[] subjectKeyIdentifier = new JcaX509ExtensionUtils()
				.createSubjectKeyIdentifier(cert.getPublicKey())
				.getKeyIdentifier();

		signedDataGenerator = new CMSSignedDataGenerator();
		signedDataGenerator
				.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().build())
						.build(new JcaContentSignerBuilder("SHA256withECDSA")
								.build(kp.getPrivate()), subjectKeyIdentifier));

	}

	/**
	 * Add person to direct trust store.
	 * 
	 * @param person
	 *            trusted person
	 * @throws Exception
	 *             if trust cannot be created
	 */
	public void trust(CMSPerson person) throws Exception {

		store = new JcaCertStoreBuilder().addCertificate(
				new JcaX509CertificateHolder(person.getCertificate())).build();
	}

	/**
	 * Get person's certificate.
	 * 
	 * @return certificate
	 */
	public X509Certificate getCertificate() {
		return cert;
	}

	/**
	 * Send enveloped message to another person.
	 * @param person person receiving message
	 * @param message message to be sent
	 * @throws CMSException if sending fails
	 */
	public void sendEnveloped(CMSPerson person, String message)
			throws CMSException {

		try {
			// Create ephemeral key pair
			KeyPair kp = SecurityUtils.createKeyPair("ECDSA");
			CMSProcessableByteArray msg = new CMSProcessableByteArray(
					message.getBytes());

			CMSCompressedDataGenerator compressedGenerator = new CMSCompressedDataGenerator();
			CMSCompressedData compressedData = compressedGenerator.generate(
					msg, new ZlibCompressor());
			CMSEnvelopedDataGenerator envelopedDataGenerator = new CMSEnvelopedDataGenerator();
			JceKeyAgreeRecipientInfoGenerator kari = new JceKeyAgreeRecipientInfoGenerator(
					CMSAlgorithm.ECDH_SHA1KDF, kp.getPrivate(), kp.getPublic(),
					CMSAlgorithm.AES128_WRAP).setProvider("BC");
			PublicKey receiverPublicKey = person.cert.getPublicKey();

			SubjectKeyIdentifier identifier = new JcaX509ExtensionUtils()
					.createSubjectKeyIdentifier(receiverPublicKey);
			kari.addRecipient(identifier.getKeyIdentifier(), receiverPublicKey);
			envelopedDataGenerator.addRecipientInfoGenerator(kari);
			
			CMSEnvelopedData enveloped = envelopedDataGenerator.generate(
					msg,
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
							.build());
			System.out.println("Sending enveloped data");
			System.out.println(new HexDumpEncoder().encode(enveloped
					.getEncoded()));
			System.out.println(ASN1Dump.dumpAsString(
					enveloped.toASN1Structure(), true));
			person.receiveEnveloped(this, enveloped.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new CMSException("Could not create envelopedData", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CMSException("Could not create envelopedData", e);
		} catch (IOException e) {
			throw new CMSException("Could not create envelopedData", e);
		}

	}

	/**
	 * Send signed message.
	 * @param person receiver
	 * @param message message to be sent
	 * @throws CMSException if CMS generation fails
	 * @throws IOException if sending fails
	 */
	public void sendSigned(CMSPerson person, String message)
			throws CMSException, IOException {
		CMSProcessableByteArray msg = new CMSProcessableByteArray(
				message.getBytes());
		CMSSignedData signed = signedDataGenerator.generate(msg, true);
		System.out.println("Sending signed data to " + person.name);

		System.out.println(new HexDumpEncoder().encode(signed.getEncoded()));
		System.out
				.println(ASN1Dump.dumpAsString(signed.toASN1Structure(), true));
		person.receiveSigned(this, signed.getEncoded());

	}

	/**
	 * Receive enveloped message.
	 * @param person sender
	 * @param message enveloped message
	 * @throws CMSException if message is not valid enveloped message
	 */
	public void receiveEnveloped(CMSPerson person, byte[] message)
			throws CMSException {
		try {
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(message);
			SubjectKeyIdentifier identifier = new JcaX509ExtensionUtils()
					.createSubjectKeyIdentifier(kp.getPublic());
			RecipientInformation recipient = (RecipientInformation) envelopedData
					.getRecipientInfos().get(
							new KeyAgreeRecipientId(identifier
									.getKeyIdentifier()));
			byte[] content = recipient
					.getContent(new JceKeyAgreeEnvelopedRecipient(kp
							.getPrivate()));
			System.out.println("Received: " + new String(content));
		} catch (Exception e) {
			throw new CMSException("Cannot read enveloped data", e);
		}
	}

	/**
	 * Receive signed CMS message.
	 * @param person sender
	 * @param message signed message
	 * @throws CMSException if message is not valid signed data message
	 */
	public void receiveSigned(CMSPerson person, byte[] message)
			throws CMSException {
		if (store != null) {
			checkTrusted(person);
		}

		byte[] subjectKeyIdentifier;
		try {
			subjectKeyIdentifier = new JcaX509ExtensionUtils()
					.createSubjectKeyIdentifier(person.cert.getPublicKey())
					.getKeyIdentifier();
			CMSSignedData signedData = new CMSSignedData(message);
			SignerInformation signer = signedData.getSignerInfos().get(
					new SignerId(subjectKeyIdentifier));
			if (signer != null) {
				boolean valid = signer
						.verify(new JcaSimpleSignerInfoVerifierBuilder()
								.build(person.cert));
				System.out.println("Received message signature verified: "
						+ valid);
				System.out.println("Received message: "
						+ new String((byte[]) signedData.getSignedContent()
								.getContent()));
			} else {
				System.out
						.println("Sender's certificate doesn't match with the message");
			}

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void checkTrusted(CMSPerson person) throws CMSException {
		try {
			X509CertSelector selector = new X509CertSelector();
			selector.setCertificate(person.getCertificate());
			Collection<? extends Certificate> certificates = store
					.getCertificates(selector);
			if (certificates.isEmpty()) {
				System.out.println("Not trusting person though claiming to be "
						+ person.name);
				throw new CMSException(name
						+ " is not trusting to person claiming to be "
						+ person.name);
			}

		} catch (CertStoreException e) {
			throw new CMSException("Can't access trusted certificate store", e);
		}
	}
}
