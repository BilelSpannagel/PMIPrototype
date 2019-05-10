import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/* Validation Authority tasked with validating certificates issued by the Certification Authority
 * 
 * 
 */

public class ValidationAuthority{
	
	/* Static initializer for the key pair generator
	 * If a keypair has already been generated, this one will be loaded from a file and used
	 * If no keypair has been generated, a new keypair gets generated and saved inside a file
	 */
	
	static KeyPair validatorKP;
	static int certificateListId = 0;

	static {
		KeyPairGenerator kPG;
		try {
			RecordsFile rf = new RecordsFile("KeyPairs.jdb", "r");
			RecordReader rr = rf.readRecord("validationAuthorityKeyPair");
			validatorKP = (KeyPair)rr.readObject();
		}
		catch (RecordsFileException c) {
			try {
				System.out.println("Validation Authority Key Pair generated");
				kPG = KeyPairGenerator.getInstance("RSA", "BC");
				kPG.initialize(1024, new SecureRandom());
				validatorKP = kPG.generateKeyPair();
				RecordsFile recordsFile = new RecordsFile("Keypairs.jdb", 64);
				RecordWriter rw = new RecordWriter("validationAuthorityKeyPair");
				rw.writeObject(validatorKP);
				recordsFile.insertRecord(rw);
				System.out.println("Key Pair saved");
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (RecordsFileException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//	static ArrayList<X509Certificate> CRL = new ArrayList<X509Certificate>();
	
	/* Static initializer for the certificate revocation list, storing revoked certificates
	 * Generates a CRL and signs it with the stored key
	 */
	
	static X509CRL CRL;

	static X500Name validationAuthority = new X500Name("CN=HFU, O=HFU, C=DE");
	static {
		X509v2CRLBuilder CRLBuilder = new X509v2CRLBuilder(validationAuthority, new Date());
		JcaContentSignerBuilder contentSignerBuilder =
		        new JcaContentSignerBuilder("SHA256WithRSAEncryption");

		    contentSignerBuilder.setProvider("BC");

		    X509CRLHolder crlHolder;
			try {
				crlHolder = CRLBuilder.build(contentSignerBuilder.build(validatorKP.getPrivate()));
			    JcaX509CRLConverter converter = new JcaX509CRLConverter();

			    converter.setProvider("BC");

			    CRL = converter.getCRL(crlHolder);
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CRLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
	
	//Validates a certificate based on the set validation dates, if it is already valid or not valid anymore
	
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
	
	//Checks if a certificate is valid at a specific date
	
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
	
	//Checks if a certificate is inside the CRL
	
	boolean validateCertificateFromCRL(X509Certificate certificateToValidate) {
		return CRL.isRevoked(certificateToValidate);
	}
	
	//Validates checking both expiration and CRL
	
	void fullValidation(X509Certificate certificateToValidate) {
		validateCertificate(certificateToValidate);
		if(validateCertificateFromCRL(certificateToValidate) == true) {
			try {
				throw new CertificateExpiredException();
			} catch (CertificateExpiredException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	/* Adds entries to the CRL
	 * Generates a new CRL with the old CRL, adding the new certificate as an entry
	 * The old CRL gets overwritten with the new CRL
	 */
	
	void addToCRL(X509Certificate certificateToAdd, int reason) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		X509v2CRLBuilder CRLBuilder = new X509v2CRLBuilder(validationAuthority, new Date());
		try {
			CRLBuilder.addCRL(new X509CRLHolder(CRL.getEncoded()));
		} catch (CRLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		CRLBuilder.addCRLEntry(certificateToAdd.getSerialNumber(), new Date(), reason);
		JcaContentSignerBuilder contentSignerBuilder =
		        new JcaContentSignerBuilder("SHA256WithRSAEncryption");

		    contentSignerBuilder.setProvider("BC");

		    X509CRLHolder crlHolder;
			try {
				crlHolder = CRLBuilder.build(contentSignerBuilder.build(validatorKP.getPrivate()));
			    JcaX509CRLConverter converter = new JcaX509CRLConverter();

			    converter.setProvider("BC");

			    CRL = converter.getCRL(crlHolder);
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CRLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
}