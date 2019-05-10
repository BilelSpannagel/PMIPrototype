import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public class Main{
	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		CertificationAuthority hfuCA = new CertificationAuthority();

		final String algorithm = "SHA256withRSA";
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		RegistrationAuthority registrationAuthority = new RegistrationAuthority();

		KeyPairGenerator kPG = KeyPairGenerator.getInstance("RSA", "BC");
		kPG.initialize(1024, new SecureRandom());
		KeyPair pair = kPG.generateKeyPair();

		X509Certificate x509c = hfuCA.createX509CertificateWithFactory(registrationAuthority.createCSR("CN=Bilel, O=HFU, C=DE", pair),sigAlgId, digAlgId);
		
		System.out.println(x509c);
		
		KeyPair pair2 = kPG.generateKeyPair();
		
		X509Certificate x509c2 = hfuCA.createX509CertificateWithFactory(registrationAuthority.createCSR("CN=Bilel, O=HFU, C=DE", pair2),sigAlgId, digAlgId);
		
		System.out.println(x509c2);
		RecordsFile recordsFile = new RecordsFile("KeyPairs.jdb", "r");
		RecordReader rr = recordsFile.readRecord("certificateFactoryKeyPair");
		KeyPair d = (KeyPair)rr.readObject();
		System.out.println("KeyPair: " + d.toString());
	}
}