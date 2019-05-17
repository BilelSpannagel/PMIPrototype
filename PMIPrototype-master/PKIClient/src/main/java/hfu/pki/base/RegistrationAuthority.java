package hfu.pki.base;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class RegistrationAuthority{

	private final CertificationAuthority ca;

	RegistrationAuthority(CertificationAuthority ca) {
		this.ca = ca;
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest csr) {
		// TODO: check CSR before CA call
		return ca.issueCertificate(csr);
	}

}