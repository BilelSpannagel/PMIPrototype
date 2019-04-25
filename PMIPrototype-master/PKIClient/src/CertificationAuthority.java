import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import org.bouncycastle.asn1.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V2CRLGenerator;

public class CertificationAuthority{
	
	static String issuer = new String();
	static ArrayList<Certificate> certificateRevocationList = new ArrayList<Certificate>();
	static String signature = new String();
	static ArrayList<Certificate> certificateList = new ArrayList<Certificate>();
	
	X509V2CRLGenerator newCRL = new X509V2CRLGenerator();
	
	static CertificateFactory certificationAuthority = new CertificateFactory();
	
	void publishPublicKey(){
		// TODO: publish Key	
	}
//	Certificate createCertificate() throws CertificateException{
//		ASN1TaggedObject obj = ASN1TaggedObject.getInstance(new Object());
//		Certificate newCertificate = Certificate.getInstance(obj, false);
//		// TODO: create Certificate	
//		certificateList.add(newCertificate);
//		return newCertificate;
//	}
	
	X509Certificate createX509CertificateWithFactory() throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException {
		X509CertificateFactory cF = new X509CertificateFactory();
		KeyPairGenerator kPG = KeyPairGenerator.getInstance("RSA", "BC");
		kPG.initialize(1024, new SecureRandom());
		KeyPair kP = kPG.generateKeyPair();
		
		return cF.generateCertificate(kP);
	}
	
	void generateSelfSignedCertificate() throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, IOException {
		 Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	        // in 2 years
	        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

	        // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	        keyPairGenerator.initialize(1024, new SecureRandom());

	        KeyPair keyPair = keyPairGenerator.generateKeyPair();

	        // GENERATE THE X509 CERTIFICATE
	        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
	        X500Principal dnName = new X500Principal("CN=John Doe");

	        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	        certGen.setSubjectDN(dnName);
	        certGen.setIssuerDN(dnName); // use the same
	        certGen.setNotBefore(validityBeginDate);
	        certGen.setNotAfter(validityEndDate);
	        certGen.setPublicKey(keyPair.getPublic());
	        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");

	        // DUMP CERTIFICATE AND KEY PAIR

//	        System.out.println(Strings.repeat("=", 80));
	        System.out.println("CERTIFICATE TO_STRING");
//	        System.out.println(Strings.repeat("=", 80));
	        System.out.println();
	        System.out.println(cert);
	        System.out.println();

//	        System.out.println(Strings.repeat("=", 80));
	        System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
//	        System.out.println(Strings.repeat("=", 80));
	        System.out.println();
	        PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
	        pemWriter.writeObject(cert);
	        pemWriter.flush();
	        System.out.println();

//	        System.out.println(Strings.repeat("=", 80));
	        System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
//	        System.out.println(Strings.repeat("=", 80));
//	        System.out.println();
	        pemWriter.writeObject(keyPair.getPrivate());
	        pemWriter.flush();
	System.out.println();
	}
	
//	void revokeCertificateBySerialNumber(Certificate certificateToRemove){
//		BigInteger convertedCertificate = certificateToRemove;
//		// TODO: revoke Certificate by Serial Number
//		//For security also requires private key);
//		Date currentDate = new Date();
//		newCRL.addCRLEntry(convertedCertificate, currentDate, 0);
//	}
	
//	void revokeCertificateBySubject(String subjectToDelete) {
//		//sollte wahrscheinliche ALLE Zertifikate von Nutzer l�schen statt nur eines
//		Certificate result = Certificate.removeCertificateBySerialNumber(subjectToDelete);
//		if(result == null) {		
//			System.out.println("Certificate doesn't exist");
//		}
//		else {
//			storeRevokedCertificate(result);
//			System.out.println("Certificate successfully revoked");
//		}
//		// TODO: revoke Certificate by Subject
//	}
	
	void storeRevokedCertificate(Certificate certificateToStore){
		certificateRevocationList.add(certificateToStore);
		// TODO: store Revoked Certificate in CRL	
	}
	
	Certificate getRevokedCertificateBySerialNumber(String serialNumberToSearch) {
		Certificate returnCertificate = null;
		for(int i = 0; i < certificateRevocationList.size(); i++) {
//			if(certificateRevocationList.get(i).getSerialNumber() == serialNumberToSearch) {
//				returnCertificate = certificateRevocationList.get(i);
//			}
		}
		return returnCertificate;
	}
	ArrayList<Certificate> getAllRevokedCertificates() {
		return certificateRevocationList;
	}
	
	void signCertificate(Certificate certificateToSign){
//		certificateToSign.si
		// TODO: sign Certificate
	}
	
	void issueCertificate(){
		// TODO: issue Certificate	
	}
	
	String getIssuer() {
		return issuer;
	}
	
	void setIssuer(String newIssuer) {
		issuer = newIssuer;
	}
	
	String getSignature() {
		return signature;
	}
	
	void setSignature(String newSignature) {
		signature = newSignature;
	}
	
}