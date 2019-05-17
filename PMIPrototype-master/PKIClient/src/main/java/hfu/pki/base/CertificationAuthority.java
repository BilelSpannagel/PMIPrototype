package hfu.pki.base;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import hfu.pki.utils.X509CertificateFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

public class CertificationAuthority {

	static String issuer = new String();

	void publishPublicKey(){
		// TODO: publish Key
	}

	X509Certificate createX509CertificateWithFactory(PKCS10CertificationRequest CertificationRequest, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
		X509CertificateFactory cF = new X509CertificateFactory();

		return cF.generateCertificate(CertificationRequest, sigAlgId, digAlgId);
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


	void revokeCertificateBySerialNumber(Certificate certificateToRemove){
		// TODO: revoke Certificate by Serial Number
		//For security should also requires private key);
	}

	void revokeCertificateBySubject(String subjectToDelete) {
		//sollte wahrscheinliche ALLE Zertifikate von Nutzer l�schen statt nur eines
		// TODO: revoke Certificate by Subject
	}

	Certificate getRevokedCertificateBySerialNumber(String serialNumberToSearch) {
		Certificate returnCertificate = null;
		// TODO: get revoked Certificate
		return returnCertificate;
	}

	void signCertificate(Certificate certificateToSign){
		// TODO: sign Certificate
	}


	String getIssuer() {
		return issuer;
	}

	void setIssuer(String newIssuer) {
		issuer = newIssuer;
	}

	public X509Certificate issueCertificate(PKCS10CertificationRequest csr) {
		return null;
	}
}