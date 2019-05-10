import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CertificationAuthority{

	static String issuer = new String();
	static ArrayList<Certificate> certificateRevocationList = new ArrayList<Certificate>();
	static String signature = new String();
	static ArrayList<Certificate> certificateList = new ArrayList<Certificate>();


	static CertificateFactory certificationAuthority = new CertificateFactory();

	void publishPublicKey(){
		// TODO: publish Key
	}

	X509Certificate createX509CertificateWithFactory(PKCS10CertificationRequest CertificationRequest, AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
		X509CertificateFactory cF = new X509CertificateFactory();

		return cF.generateCertificate(CertificationRequest, sigAlgId, digAlgId);
	}


	void revokeCertificateBySerialNumber(Certificate certificateToRemove){
		// TODO: revoke Certificate by Serial Number
		//For security should also requires private key);
	}

	void revokeCertificateBySubject(String subjectToDelete) {
		//sollte wahrscheinliche ALLE Zertifikate von Nutzer l�schen statt nur eines
		// TODO: revoke Certificate by Subject
	}

	void storeRevokedCertificate(Certificate certificateToStore){
		certificateRevocationList.add(certificateToStore);
		// TODO: store Revoked Certificate in CRL
	}

	Certificate getRevokedCertificateBySerialNumber(String serialNumberToSearch) {
		Certificate returnCertificate = null;
		// TODO: get revoked Certificate
		return returnCertificate;
	}
	ArrayList<Certificate> getAllRevokedCertificates() {
		return certificateRevocationList;
	}

	void signCertificate(Certificate certificateToSign){
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