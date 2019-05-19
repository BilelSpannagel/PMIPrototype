package hfu.pki.base;

import hfu.pki.database.DatabaseFacade;
import hfu.pki.utils.Configurations;
import hfu.pki.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

public class CertificationAuthority {

	private final AlgorithmIdentifier sigAlgId;
	private final AlgorithmIdentifier digAlgId;
	private final X509Certificate caCertificate;
	private final KeyPair caKeyPair;
	private final DatabaseFacade databaseFacade;

	public CertificationAuthority(DatabaseFacade databaseFacade) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException {
		String algorithm = "SHA256withRSA";
		this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		this.digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		this.caKeyPair = Utils.loadKeyPair(Configurations.CA_KEYPAIR_PATH, Configurations.CA_PRIVATE_KEY_FILENAME, Configurations.CA_PUBLIC_KEY_FILENAME);
		this.caCertificate = Utils.loadCertificateFromPEM(Configurations.CA_CERTIFICATE);
		this.databaseFacade = databaseFacade;
	}

	public X509Certificate getCACertificate() {
		return this.caCertificate;
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest certificationRequest) throws SecurityException, CertificateException, OperatorCreationException, IOException {
		return createCertificate(certificationRequest);
	}

	private X509Certificate createCertificate(PKCS10CertificationRequest certificationRequest) throws SecurityException, CertificateException, OperatorCreationException, IOException {
		X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuer,
				BigInteger.valueOf(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() - 50000),
				new Date(System.currentTimeMillis() + 50000),
				certificationRequest.getSubject(),
				certificationRequest.getSubjectPublicKeyInfo());

		// Certificate extensions
		certGen.addExtension(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
		certGen.addExtension(new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded()));
		certGen.addExtension(new Extension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded()));
		certGen.addExtension(new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")).getEncoded()));

		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKeyPair.getPrivate().getEncoded());
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
		X509CertificateHolder certificateHolder = certGen.build(sigGen);

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		gen.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(sigGen, certificateHolder));
		X509Certificate certificate = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder );

		// TODO: use storage result. On failure throw not stored exception
		boolean isStored = databaseFacade.storeCertificate(certificate);

		return certificate;
	}

	boolean revokeCertificate(String serialNumber){
		// TODO: revoke Certificate
		// For security should also requires private key?
		return databaseFacade.revokeCertificate(serialNumber);
	}

	X509Certificate getCertificate(String serialNumber) {
		// TODO: get certificate
		return databaseFacade.getCertificate(serialNumber);
	}
}