//import java.util.ArrayList;
//import java.util.Date;
//
//import org.bouncycastle.jcajce.provider.keystore.PKCS12;
//
//public class Certificate{
//	String serialNumber = new String();
//	String subject = new String();
//	String issuer = new String();
//	Date notBefore = new Date();
//	Date notAfter = new Date();
//	//Key Usage
//	//Extended Key Usage
//	PKCS12 publicKey = new PKCS12();
//	//Signature Algorithm
//	//Signature
////	Boolean hasPublicKey = false;
//	
//	static ArrayList<Certificate> certificateList = new ArrayList<Certificate>();
//	
//	Certificate(String newSerialNumber, String newIssuer, String newSubject, Date newNotBefore, Date newNotAfter, PKCS12 publicKey){
//		setSerialNumber(newSerialNumber);
//		setIssuer(newIssuer);
//		setSubject(newSubject);
//		setNotBefore(newNotBefore);
//		setNotAfter(newNotAfter);
//		setPublicKey(publicKey);
//		certificateList.add(this);
//	}
////	Certificate(PKCS12 ownPublicKey){
////		certificateList.add(this);
////		setHasPublicKey(true);
////	}
//	
//	String getSerialNumber() {
//		return this.serialNumber;
//	}
//	
//	void setSerialNumber(String newSerialNumber) {
//		this.serialNumber = newSerialNumber;
//	}
//	
//	String getSubject() {
//		return this.subject;
//	}
//	
//	void setSubject(String newSubject) {
//		this.subject = newSubject;
//	}
//	
//	String getIssuer() {
//		return this.issuer;
//	}
//	
//	void setIssuer(String newIssuer) {
//		this.issuer = newIssuer;
//	}
//	
//	Date getNotBefore() {
//		return this.notBefore;
//	}
//	
//	void setNotBefore(Date newNotBefore) {
//		this.notBefore = newNotBefore;
//	}
//	
//	Date getNotAfter() {
//		return this.notAfter;
//	}
//	
//	void setNotAfter(Date newNotAfter) {
//		this.notAfter = newNotAfter;
//	}
//	
//	PKCS12 getPublicKey() {
//		return this.publicKey;
//	}
//	
//	void setPublicKey(PKCS12 newPublicKey) {
//		this.publicKey = newPublicKey;
//	}
//	
//	static Certificate removeCertificateBySerialNumber(String serialNumberToDelete) {
//		Certificate returnCertificate = null;
//		for(int i = 0; i < certificateList.size(); i++) {
//			if(certificateList.get(i).getSerialNumber() == serialNumberToDelete) {
//				returnCertificate = certificateList.get(i);
//				certificateList.remove(i);
//			}
//		}
//		return returnCertificate;
//	}
//	static Certificate removeCertificateBySubject(String subjectToDelete) {
//		Certificate returnCertificate = null;
//		for(int i = 0; i < certificateList.size(); i++) {
//			if(certificateList.get(i).getSubject() == subjectToDelete) {
//				returnCertificate = certificateList.get(i);
//				certificateList.remove(i);
//			}
//		}
//		return returnCertificate;
//	}
//	static Certificate getCertificateBySerialNumber(String serialNumberToSearch) {
//		Certificate returnCertificate = null;
//		for(int i = 0; i < certificateList.size(); i++) {
//			if(certificateList.get(i).getSerialNumber() == serialNumberToSearch) {
//				returnCertificate = certificateList.get(i);
//			}
//		}
//		return returnCertificate;
//	}
//	
////	Boolean getHasPublicKey() {
////		return this.hasPublicKey;
////	}
////	
////	void setHasPublicKey(Boolean newHasPublicKey) {
////		this.hasPublicKey = newHasPublicKey;
////	}
//	
//}