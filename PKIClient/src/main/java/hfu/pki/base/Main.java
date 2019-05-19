package hfu.pki.base;

import hfu.pki.database.DatabaseFacade;
import hfu.pki.utils.Utils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

public class Main{
	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		DatabaseFacade databaseFacade = new DatabaseFacade();
		CertificationAuthority certificationAuthority = new CertificationAuthority(databaseFacade);
		RegistrationAuthority registrationAuthority = new RegistrationAuthority(certificationAuthority);

		System.out.println("CA certificate...");
		System.out.println(certificationAuthority.getCACertificate());
		System.out.println();

		// Create CSR for certificate 1
		KeyPair pair = Utils.createKeyPair();
		PKCS10CertificationRequest csr = Utils.createCSR("CN=Bilel_1, O=HFU, C=DE", pair);

		// Create first certificate
		X509Certificate certificate = registrationAuthority.issueCertificate(csr);
		System.out.println("Issued certificate...");
		System.out.println(certificate);
		System.out.println();

		// Only store when necessary
		// Utils.storeCertificateAsPEM(certificate, "cert_1.pem");
		// X509Certificate loadedCertificate = Utils.loadCertificateFromPEM("src/main/resources/cert_1.pem");
		// Utils.storeKeyPair(pair, ".", "private_1.key", "public_1.key");
		// KeyPair loadedKeyPair = Utils.loadKeyPair("src/main/resources", "private_1.key", "public_1.key");

		// Create CSR for certificate 2
		pair = Utils.createKeyPair();
		csr = Utils.createCSR("CN=Bilel2, O=HFU, C=DE", pair);

		// Create second certificate
		certificate = registrationAuthority.issueCertificate(csr);
		System.out.println("Issued certificate...");
		System.out.println(certificate);
		System.out.println();

		// Only store when necessary
		// Utils.storeCertificateAsPEM(certificate, "cert_2.pem");
		// X509Certificate loadedCertificate = Utils.loadCertificateFromPEM("src/main/resources/cert_2.pem");
		// Utils.storeKeyPair(pair, ".", "private_2.key", "public_2.key");
		// KeyPair loadedKeyPair = Utils.loadKeyPair("src/main/resources", "private_2.key", "public_2.key");

	}
}