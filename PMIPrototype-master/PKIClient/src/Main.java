import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;

public class Main{
	public static void main(String[] args) throws Exception {
//		CertificationAuthority hfuCA = new CertificationAuthority();
//		hfuCA.setIssuer("HFU");
//		Date today = new Date();
//		Date tomorrow = new Date();
//		Calendar calendar = Calendar.getInstance();
//		calendar.setTime(tomorrow);
//		calendar.add(Calendar.DATE, 1);
//		tomorrow = calendar.getTime();
//		PKCS12 myPublicKey = new PKCS12();
//		Certificate myCertificate = hfuCA.createCertificate("000001", "Bilel", today, tomorrow, myPublicKey);
//		System.out.println(myCertificate.getSerialNumber());
//		System.out.println(myCertificate.getSubject());
//		System.out.println(myCertificate.getIssuer());
//		System.out.println(myCertificate.getNotBefore());
//		System.out.println(myCertificate.getNotAfter());
//		System.out.println(myCertificate.getPublicKey());
//		
//		System.out.println(Certificate.getCertificateBySerialNumber("000001"));
//		for(int i = 0; i < Certificate.certificateList.size(); i++) {
//			System.out.println("Certificate #" + i);
//			System.out.println(Certificate.certificateList.get(i));
//		}
//		
//		System.out.println(hfuCA.getIssuer());
//		hfuCA.revokeCertificateBySerialNumber("000001");
//		for(int i = 0; i < Certificate.certificateList.size(); i++) {
//			System.out.println("Certificate #" + i);
//			System.out.println(Certificate.certificateList.get(i));
//		}
//		for(int i = 0; i < CertificationAuthority.certificateRevocationList.size(); i++) {
//			System.out.println("Revoked Certificate #" + i);
//			System.out.println(CertificationAuthority.certificateRevocationList.get(i));
//		}
		
		
//		String user = new String();
//		ASN1TaggedObject newSequence;
//		newSequence = ASN1TaggedObject.getInstance(user);
//		Certificate newCertificate;
//		newCertificate = Certificate.getInstance(newSequence, true);
//		CertificateFactory newCertificateFactory = new CertificateFactory();
//		InputStream certificateInput = null;
//		try {
//			newCertificateFactory.engineGenerateCertificate(certificateInput);
//		} catch (CertificateException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		CertificationAuthority hfuCA = new CertificationAuthority();
		
		String myString = "Ich darf keinen leeren InputStream haben";
		

		hfuCA.generateSelfSignedCertificate();
		X509Certificate x509c = hfuCA.createX509CertificateWithFactory();
//		Certificate cert = hfuCA.createCertificate();
		
		System.out.println(x509c);
//		System.out.println(cert);
		X509Certificate test;
		SubjectPublicKeyInfo subjectPublicKeyInfo = null;
		X500Name subjectDN = new X500Name("C=DE,O=Organiztion");
		PrivateKey issuerPrivateKey = null;
		long serialNumber = 1;
		String signatureAlgorithm = "SHA256WithRSA";
		test = Test.createSelfsignedCert(signatureAlgorithm, subjectDN, subjectPublicKeyInfo, issuerPrivateKey, serialNumber);
		System.out.println(test);
		
	}
	
	
}