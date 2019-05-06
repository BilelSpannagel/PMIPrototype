import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

public class ValidationAuthority{
//	boolean validateCertificate(X509Certificate certificateToValidate) throws CertificateExpiredException, CertificateNotYetValidException{
//		certificateToValidate.checkValidity();
//		// TODO: validate Certificate	
//	}
	static ArrayList<X509Certificate> CRL = new ArrayList<X509Certificate>();
	
	void validateCertificate(X509Certificate certificateToValidate) {
		try {
			certificateToValidate.checkValidity();
		} catch (CertificateExpiredException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void validateDate(X509Certificate certificateToValidate, Date date) {
		try {
			certificateToValidate.checkValidity(date);
		} catch (CertificateExpiredException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void validateCertificateFromCRL(X509Certificate certificateToValidate) {
		for(int i = 0; i < CRL.size(); i++) {
			if(certificateToValidate == CRL.get(i)) {
				try {
					throw new CertificateExpiredException();
				} catch (CertificateExpiredException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	void addToCLR(X509Certificate certificateToAdd) {
		CRL.add(certificateToAdd);
	}
}