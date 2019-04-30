import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class X509CertificateFactory{
    // create the keys
		
	public X509Certificate generateCertificate(KeyPair pair, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateException, OperatorCreationException, IOException {
		

		// generate the certificate
		X509v3CertificateBuilder  certGen = new X509v3CertificateBuilder(new X500Name("CN=Test Certificate"), BigInteger.valueOf(System.currentTimeMillis()), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), new X500Name("CN=Test Certificate"), SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
		

        
        certGen.addExtension(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
        
        certGen.addExtension(new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded()));
        
        certGen.addExtension(new Extension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded()));
        
        certGen.addExtension(new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")).getEncoded()));
        
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
        
        X509CertificateHolder certificateHolder = certGen.build(sigGen);
        

        return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder );
	}
}