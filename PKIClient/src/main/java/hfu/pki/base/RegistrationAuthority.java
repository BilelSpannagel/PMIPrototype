package hfu.pki.base;

import hfu.pki.utils.Configurations;
import hfu.pki.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class RegistrationAuthority{
	private final AlgorithmIdentifier sigAlgId;
	private final AlgorithmIdentifier digAlgId;
	private final CertificationAuthority ca;
	private final X509Certificate raCertificate;
	private final KeyPair raKeyPair;

	RegistrationAuthority(CertificationAuthority ca) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
		String algorithm = "SHA256withRSA";
		this.ca = ca;
		this.raKeyPair = Utils.loadKeyPair(Configurations.CA_PRIVATE_KEY_FILENAME, Configurations.CA_PUBLIC_KEY_FILENAME);
		this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		this.digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		this.raCertificate = Utils.loadCertificateFromPEM(Configurations.CA_CERTIFICATE);
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws CertificateException, OperatorCreationException, IOException {
		// TODO: check CSR before CA call
		return ca.issueCertificate(csr);
	}
	public X509Certificate issueCertificate(X500Name cn, PublicKey publicKey) throws OperatorCreationException, CertificateException, IOException {
		PKCS10CertificationRequestBuilder p10Builder = new PKCS10CertificationRequestBuilder(cn, new SubjectPublicKeyInfo(digAlgId, publicKey.getEncoded()));
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(raKeyPair.getPrivate());
		return issueCertificate(p10Builder.build(signer));
	}


}