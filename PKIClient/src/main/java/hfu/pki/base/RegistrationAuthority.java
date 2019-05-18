package hfu.pki.base;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class RegistrationAuthority{

	private final CertificationAuthority ca;

	RegistrationAuthority(CertificationAuthority ca) {
		this.ca = ca;
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws CertificateException, OperatorCreationException, IOException {
		// TODO: check CSR before CA call
		return ca.issueCertificate(csr);
	}

}