import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class X509CertificateFactory{
	static KeyPair issuerKP;
	static int certificateListId = 0;
	
	/* Static initializer for the key pair generator
	 * If a keypair has already been generated, this one will be loaded from a file and used
	 * If no keypair has been generated, a new keypair gets generated and saved inside a file
	 */

	static {
		KeyPairGenerator kPG;
		try {
			RecordsFile rf = new RecordsFile("KeyPairs.jdb", "r");
			RecordReader rr = rf.readRecord("certificateFactoryKeyPair");
			issuerKP = (KeyPair)rr.readObject();
		}
		catch (RecordsFileException c) {
			try {
				System.out.println("CertificateFactory Key Pair generated");
				kPG = KeyPairGenerator.getInstance("RSA", "BC");
				kPG.initialize(1024, new SecureRandom());
				issuerKP = kPG.generateKeyPair();
				RecordsFile recordsFile = new RecordsFile("KeyPairs.jdb", 64);
				RecordWriter rw = new RecordWriter("certificateFactoryKeyPair");
				rw.writeObject(issuerKP);
				recordsFile.insertRecord(rw);
				System.out.println("Key Pair saved");
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (RecordsFileException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	static X500Name issuer = new X500Name("CN=HFU, O=HFU, C=DE");

	// create the keys


	public X509Certificate generateCertificate(PKCS10CertificationRequest CertificationRequest, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException {		


		// generate the certificate
		X509v3CertificateBuilder  certGen = new X509v3CertificateBuilder(CertificationRequest.getSubject(), BigInteger.valueOf(System.currentTimeMillis()), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), issuer, CertificationRequest.getSubjectPublicKeyInfo());

		certGen.addExtension(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));

		certGen.addExtension(new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded()));

		certGen.addExtension(new Extension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded()));

		certGen.addExtension(new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")).getEncoded()));



		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(issuerKP.getPrivate().getEncoded());
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

		X509CertificateHolder certificateHolder = certGen.build(sigGen);

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		gen.addSignerInfoGenerator(
				new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
				.build(sigGen, certificateHolder));
		
		//Stores the certificates inside a file, if the file doesn't exist creates it
		
		try {
			RecordsFile rf = new RecordsFile("certificateList.jdb", 64);
			RecordWriter rw = new RecordWriter(String.valueOf(certificateListId));
			rw.writeObject(new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder ).toString());
			rf.insertRecord(rw);
		} catch (RecordsFileException e) {
			try {
				RecordsFile rf = new RecordsFile("certificateList.jdb", "rw");
				RecordWriter rw = new RecordWriter(String.valueOf(certificateListId));
				rw.writeObject(new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder ).toString());
				rf.insertRecord(rw);
			} catch (RecordsFileException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		certificateListId++;
		Path pemPath = Paths.get("C:\\Users\\Bilel Spannagel\\eclipse-workspace\\PKIClient\\src\\" + new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder ).getSerialNumber() + ".pem");
		try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(pemPath.toFile()))){
			writer.writeObject((new PemObject(new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder ).getSerialNumber() + ".pem", new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder ).getEncoded())));
		}

		return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder );
	}
}