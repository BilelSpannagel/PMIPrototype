package hfu.pki.utils;

import hfu.pki.database.RecordReader;
import hfu.pki.database.RecordWriter;
import hfu.pki.database.RecordsFile;
import hfu.pki.database.RecordsFileException;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509CertificateFactory {
	private static KeyPair issuerKP;
	public static int certificateListId;

	/* Static initializer for the key pair generator
	 * If a keypair has already been generated, this one will be loaded from a file and used
	 * If no keypair has been generated, a new keypair gets generated and saved inside a file
	 */

	// TODO: decide between singleton and static calls
	static {
		try {
			RecordsFile rf = new RecordsFile("KeyPairs.jdb", "r");
			RecordReader rr = rf.readRecord("certificateFactoryKeyPair");
			issuerKP = (KeyPair)rr.readObject();
		}
		catch (RecordsFileException c) {
			try {
				System.out.println("CertificateFactory Key Pair generated");
				issuerKP = Utils.createKeyPair();
				RecordsFile recordsFile = new RecordsFile("KeyPairs.jdb", 64);
				RecordWriter rw = new RecordWriter("certificateFactoryKeyPair");
				rw.writeObject(issuerKP);
				recordsFile.insertRecord(rw);
				System.out.println("Key Pair saved");
			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	public X509Certificate createCertificate(PKCS10CertificationRequest certificationRequest, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) throws SecurityException, CertificateException, OperatorCreationException, IOException {
		X500Name issuer = new X500Name("CN=HFU, O=HFU, C=DE");
		X509v3CertificateBuilder  certGen = new X509v3CertificateBuilder(issuer,
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

		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(issuerKP.getPrivate().getEncoded());
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
		X509CertificateHolder certificateHolder = certGen.build(sigGen);

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		gen.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(sigGen, certificateHolder));

		return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder );
	}


}