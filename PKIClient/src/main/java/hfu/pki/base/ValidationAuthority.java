package hfu.pki.base;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import hfu.pki.database.*;
import hfu.pki.utils.Configurations;
import hfu.pki.utils.Utils;
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

	private final KeyPair vaKeyPair;
	private X509CRL CRL;
	private final DatabaseFacade databaseFacade;
	private final X509Certificate vaCertificate;

	public ValidationAuthority(DatabaseFacade databaseFacade) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException, CRLException {
		this.vaKeyPair = Utils.loadKeyPair(Configurations.CA_PRIVATE_KEY_FILENAME, Configurations.CA_PUBLIC_KEY_FILENAME);
		this.CRL = Utils.loadCRL(Configurations.VA_CRL_FILENAME);
		this.vaCertificate = Utils.loadCertificateFromPEM(Configurations.CA_CERTIFICATE);
		this.databaseFacade = databaseFacade;
	}
	X509Certificate getVaCertificate(){
		return vaCertificate;
	}
	//Validates checking both expiration and CRL
	boolean isValid(X509Certificate certificateToValidate) throws CertificateExpiredException, CertificateNotYetValidException{
		try{
			certificateToValidate.checkValidity();
		} catch (Exception e){
			e.printStackTrace();;
			return false;
		}
		if(CRL.isRevoked(certificateToValidate)) {
			return false;
		}
		return true;
	}

	/* Adds entries to the CRL
	 * Generates a new CRL with the old CRL, adding the new certificate as an entry
	 * The old CRL gets overwritten with the new CRL
	 */
	void addToCRL(X509Certificate certificateToAdd, int reason) throws CRLException, IOException, OperatorCreationException{
			X509v2CRLBuilder CRLBuilder = new X509v2CRLBuilder(new X500Name(vaCertificate.getIssuerX500Principal().getName()), new Date());
			CRLBuilder.addCRL(new X509CRLHolder(CRL.getEncoded()));
			CRLBuilder.addCRLEntry(certificateToAdd.getSerialNumber(), new Date(), reason);
			JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
			contentSignerBuilder.setProvider("BC");
			X509CRLHolder crlHolder;
			crlHolder = CRLBuilder.build(contentSignerBuilder.build(vaKeyPair.getPrivate()));
			JcaX509CRLConverter converter = new JcaX509CRLConverter();
			converter.setProvider("BC");
			CRL = converter.getCRL(crlHolder);
			Utils.storeCRLAsPEM(CRL);
	}
}