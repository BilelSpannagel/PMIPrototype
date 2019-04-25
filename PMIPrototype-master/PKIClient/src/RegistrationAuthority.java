import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import com.serialization.KeyPairReader;
import com.serialization.ObjectSerializer;

public class RegistrationAuthority{
	void createCertificateApplication(String subject, String pubFileName, String privFileName) throws Exception {

        KeyPair keyPair = KeyPairReader.readKeyPair(pubFileName, privFileName);
        PKCS10CertificationRequest csr = createCSR(subject, keyPair);

        BufferedReader rd = Files.newBufferedReader(Paths.get("Filename.txt"));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = rd.readLine()) != null) {
            builder.append(line);
        }

        Document doc = Jsoup.parse(builder.toString());
        Element link = doc.select("a").first();
        String linkHref = link.attr("href");
        System.out.println(linkHref);

        Pattern pattern = Pattern.compile("Success:(\\w+)_Pending:(\\w+)_Failure:(\\w+)_TransId:([a-zA-Z0-9_-]+)_Subject:([a-zA-Z0-9_-]+)");
        Matcher matcher = pattern.matcher(linkHref);
        if (matcher.find()) {
            // Whole content
            // System.out.println(matcher.group(0));
            System.out.println("IsSuccess: " + matcher.group(1));
            System.out.println("IsPending: " + matcher.group(2));
            System.out.println("IsFailure: " + matcher.group(3));
            System.out.println("TransId: " + matcher.group(4));
            System.out.println("Subject: " + matcher.group(5));
            System.out.println("RequestString: " + matcher.group(5) + "/" + matcher.group(4));
        }
    }
	
	private PKCS10CertificationRequest createCSR(String subject, KeyPair requestKeyPair) throws OperatorCreationException, NoSuchAlgorithmException {
        X500Principal entitySubject = new X500Principal(subject);
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, requestKeyPair.getPublic());

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(requestKeyPair.getPrivate());
        return csrBuilder.build(csrSigner);
    }
	void createCertificateApplicationWithPublicKey(){
		// TODO: create Request		
	}
	void searchCertificateApplicationById(){
		// TODO: search Certifciate by ID
	}
	void searchCertificateApplicationByName(){
		// TODO: search Certificate by Name	
	}
	void createCertificateRequest(){
		// TODO: create Request		
	}
	void createCertificateRequestWithPublicKey(){
		// TODO: create Request		
	}
	void deleteCertificateRequest(){
		// TODO: delete Request	
	}
	void deleteCertificateApplication(){
		// TODO: delete Application
	}
}