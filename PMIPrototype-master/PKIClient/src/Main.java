import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public class Main{
	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		CertificationAuthority hfuCA = new CertificationAuthority();

		hfuCA.generateSelfSignedCertificate();
		final String algorithm = "SHA256withRSA";
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		X509Certificate x509c = hfuCA.createX509CertificateWithFactory(sigAlgId, digAlgId);

		System.out.println(x509c);
		X509Certificate test;
		X500Name subjectDN = new X500Name("C=DE,O=Organiztion");
		long serialNumber = 000000000000001;
		KeyPairGenerator kPG = KeyPairGenerator.getInstance("RSA", "BC");
		kPG.initialize(1024, new SecureRandom());
		KeyPair pair = kPG.generateKeyPair();
		test = Test.createSelfsignedCert(algorithm, subjectDN, SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()), pair.getPrivate(), serialNumber);
		System.out.println(test);
	}

}