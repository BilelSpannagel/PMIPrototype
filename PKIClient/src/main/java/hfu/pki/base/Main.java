package hfu.pki.base;

import hfu.pki.database.RecordReader;
import hfu.pki.database.RecordsFile;
import hfu.pki.utils.Utils;
import hfu.pki.utils.X509CertificateFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

public class Main{
	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		CertificationAuthority certificationAuthority = new CertificationAuthority();
		RegistrationAuthority registrationAuthority = new RegistrationAuthority(certificationAuthority);

		// Create CSR
		KeyPair pair = Utils.createKeyPair();
		PKCS10CertificationRequest csr = Utils.createCSR("CN=Bilel, O=HFU, C=DE", pair);

		// Create certificate
		X509Certificate x509c = registrationAuthority.issueCertificate(csr);
		Utils.storeCertificateAsPEM(x509c);

		System.out.println("######################################### Reading Certificate #########################################");
		System.out.println(certificationAuthority.readCertificate(x509c.getSerialNumber()));
		System.out.println("######################################### Certificate read #########################################");
		System.out.println(x509c);

		// Create second certificate
		KeyPair pair2 = Utils.createKeyPair();
		csr = Utils.createCSR("CN=Bilel, O=HFU, C=DE", pair2);
		X509Certificate x509c2 = registrationAuthority.issueCertificate(csr);
		Utils.storeCertificateAsPEM(x509c2);

		System.out.println(x509c2);
		RecordsFile recordsFile = new RecordsFile("KeyPairs.jdb", "r");
		RecordReader rr = recordsFile.readRecord("certificateFactoryKeyPair");
		KeyPair d = (KeyPair)rr.readObject();
		System.out.println("KeyPair: " + d.toString());
		
		RecordsFile recordsFile2 = new RecordsFile("certificateList.jdb", "r");
		rr = recordsFile2.readRecord(String.valueOf(X509CertificateFactory.certificateListId - 1));
		
		String c = (String) rr.readObject();
		System.out.println("X509Certificate: " + c);
	}
}