import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jcajce.provider.keystore.PKCS12;

public class Main{
	public static void main(String[] args) {
		CertificationAuthority hfuCA = new CertificationAuthority();
		hfuCA.setIssuer("HFU");
		Date today = new Date();
		Date tomorrow = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(tomorrow);
		calendar.add(Calendar.DATE, 1);
		tomorrow = calendar.getTime();
		PKCS12 myPublicKey = new PKCS12();
		Certificate myCertificate = hfuCA.createCertificate("000001", "Bilel", today, tomorrow, myPublicKey);
		System.out.println(myCertificate.getSerialNumber());
		System.out.println(myCertificate.getSubject());
		System.out.println(myCertificate.getIssuer());
		System.out.println(myCertificate.getNotBefore());
		System.out.println(myCertificate.getNotAfter());
		System.out.println(myCertificate.getPublicKey());
		
		System.out.println(Certificate.getCertificateBySerialNumber("000001"));
		for(int i = 0; i < Certificate.certificateList.size(); i++) {
			System.out.println("Certificate #" + i);
			System.out.println(Certificate.certificateList.get(i));
		}
		
		System.out.println(hfuCA.getIssuer());
		hfuCA.revokeCertificateBySerialNumber("000001");
		for(int i = 0; i < Certificate.certificateList.size(); i++) {
			System.out.println("Certificate #" + i);
			System.out.println(Certificate.certificateList.get(i));
		}
		for(int i = 0; i < CertificationAuthority.certificateRevocationList.size(); i++) {
			System.out.println("Revoked Certificate #" + i);
			System.out.println(CertificationAuthority.certificateRevocationList.get(i));
		}
		
	}
	
	
}