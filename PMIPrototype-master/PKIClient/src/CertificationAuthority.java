import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;

public class CertificationAuthority{
	
	static String issuer = new String();
	static ArrayList<Certificate> certificateRevocationList = new ArrayList<Certificate>();
	static String signature = new String();
	
	void publishPublicKey(){
		// TODO: publish Key	
	}
	Certificate createCertificate(String newSerialNumber, String newSubject, Date newNotBefore, Date newNotAfter, PKCS12 publicKey){
		Certificate newCertificate = new Certificate(newSerialNumber, issuer, newSubject, newNotBefore, newNotAfter, publicKey);
		return newCertificate;
		// TODO: create Certificate	
	}
	
	void revokeCertificateBySerialNumber(String serialNumberToDelete){
		// TODO: revoke Certificate by Serial Number
		Certificate result = Certificate.removeCertificateBySerialNumber(serialNumberToDelete);
		if(result == null) {		
			System.out.println("Certificate doesn't exist");
		}
		else {
			certificateRevocationList.add(result);
			System.out.println("Certificate successfully revoked");
		}
		// Funktioniert das so überhaupt? Fügt immer wieder das Certifikat "result" hinzu
	}
	
	void revokeCertificateBySubject(String subjectToDelete) {
		//sollte wahrscheinliche ALLE Zertifikate von Nutzer löschen statt nur eines
		Certificate result = Certificate.removeCertificateBySerialNumber(subjectToDelete);
		if(result == null) {		
			System.out.println("Certificate doesn't exist");
		}
		else {
			storeRevokedCertificate(result);
			System.out.println("Certificate successfully revoked");
		}
		// TODO: revoke Certificate by Subject
	}
	
	void storeRevokedCertificate(Certificate certificateToStore){
		certificateRevocationList.add(certificateToStore);
		// TODO: store Revoked Certificate in CRL	
	}
	
	Certificate getRevokedCertificateBySerialNumber(String serialNumberToSearch) {
		Certificate returnCertificate = null;
		for(int i = 0; i < certificateRevocationList.size(); i++) {
			if(certificateRevocationList.get(i).getSerialNumber() == serialNumberToSearch) {
				returnCertificate = certificateRevocationList.get(i);
			}
		}
		return returnCertificate;
	}
	ArrayList<Certificate> getAllRevokedCertificates() {
		return certificateRevocationList;
	}
	
	void signCertificate(){
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