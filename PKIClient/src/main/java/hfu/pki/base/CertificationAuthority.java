package hfu.pki.base;

import hfu.pki.utils.X509CertificateFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificationAuthority {

	private final AlgorithmIdentifier sigAlgId;
	private final AlgorithmIdentifier digAlgId;
	private final X509CertificateFactory certificateFactory;

	public CertificationAuthority() {
		String algorithm = "SHA256withRSA";
		this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
		this.digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		this.certificateFactory = new X509CertificateFactory();
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest CertificationRequest) throws SecurityException, CertificateException, OperatorCreationException, IOException {
		return certificateFactory.generateCertificate(CertificationRequest, sigAlgId, digAlgId);
	}
	
	String readCertificate(BigInteger serialNumber) throws IOException {
		try {
			X509Certificate cert = null;
			PEMParser reader = new PEMParser(new FileReader("C:\\Users\\Bilel Spannagel\\eclipse-workspace\\PKIClient\\src\\" + serialNumber + ".pem"));
			PemObject object = reader.readPemObject();
			cert = (X509Certificate)reader.readObject();
			reader.close();
			byte[] binaries = object.getContent();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			os.write(binaries, 0, binaries.length);
			ASN1InputStream input = new ASN1InputStream(os.toByteArray());
			ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
			input.close();
			return asn1.toString();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}


	void revokeCertificateBySerialNumber(String serialNumber){
		// TODO: revoke Certificate by Serial Number
		// For security should also requires private key?
	}

	X509Certificate getCertificateBySerialNumber(String serialNumber) {
		// TODO: get certificate
		return null;
	}
}