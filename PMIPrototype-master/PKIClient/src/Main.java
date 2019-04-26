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

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		CertificationAuthority hfuCA = new CertificationAuthority();

		String myString = "Ich darf keinen leeren InputStream haben";


		hfuCA.generateSelfSignedCertificate();
		final String algorithm = "MD2WITHRSA";
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		X509Certificate x509c = hfuCA.createX509CertificateWithFactory(sigAlgId, digAlgId);
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