import com.serialization.*;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
//import org.bouncycastle.util.encoders.Base64;
import java.util.Base64;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.w3c.dom.Attr;
import org.bouncycastle.asn1.x509.Attribute;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 09.05.17.
 */
class CertificateManagement {

    void createCertificateRequest(String subject, String pubFileName, String privFileName) throws Exception {
        // Example subject: "M"
        // Example public key: "/home/kevin/Projects/JavaProjects/PMI/clientKeys/public_key.der"
        // Example private key: "/home/kevin/Projects/JavaProjects/PMI/clientKeys/private_key.der"

        HttpClient client = new DefaultHttpClient();
        KeyPair keyPair = KeyPairReader.readKeyPair(pubFileName, privFileName);
        PKCS10CertificationRequest csr = createCSR(subject, keyPair);
        String serializedCSR = ObjectSerializer.toString(csr);
        String url = "http://localhost:8080/PMITest_war_exploded/pki/request/create/" + serializedCSR;
        System.out.println("Url: " + url);

        HttpPost post = new HttpPost(url);
        HttpResponse response = client.execute(post);

        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
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

    void pollCertificate(String subject, String transactionId) throws IOException {
        pollCertificate(subject + "/" + transactionId);
    }

    void pollCertificate(String requestString) throws IOException {
        HttpClient client = new DefaultHttpClient();
        String url = "http://localhost:8080/PMITest_war_exploded/pki/poll/" + requestString;
        System.out.println("Url: " + url);
        HttpGet get = new HttpGet(url);
        HttpResponse response = client.execute(get);
        X509Certificate certificate = convertToCertificate(response);
        System.out.println(certificate == null ? "No certificate found." : certificate);
        storeCertificateDialog(certificate);
    }

    void getCertificate(String serialNumber) throws IOException, ClassNotFoundException {
        HttpClient client = new DefaultHttpClient();
        String url = "http://localhost:8080/PMITest_war_exploded/pki/get/" + serialNumber;
        System.out.println("Url: " + url);
        HttpGet get = new HttpGet(url);
        HttpResponse response = client.execute(get);
        X509Certificate certificate = convertToCertificate(response);
        System.out.println(certificate == null ? "No certificate found." : certificate);
        storeCertificateDialog(certificate);
    }


    private void storeCertificateDialog(X509Certificate certificate) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Store certificate [Y/N]?");
        boolean decided = false;
        while (!decided) {
            String text = scanner.nextLine();
            if ("Y".equals(text)) {
                storeCertificate(certificate);
                return;
            } else if ("N".equals(text)) {
                return;
            }
        }
    }

    private void storeAttributeCertificateDialog(X509AttributeCertificateHolder holder) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Store AttributeCertificate [Y/N]?");
        boolean decided = false;
        while (!decided) {
            String text = scanner.nextLine();
            if ("Y".equals(text)) {
                storeAttributeCertificate(holder);
                return;
            } else if ("N".equals(text)) {
                return;
            }
        }
    }

    void storeCertificate(X509Certificate certificate) {
        try {
            System.out.print("Enter file name:");
            String filename = new Scanner(System.in).nextLine();
            Writer writer = new FileWriter(filename);
            JcaPEMWriter jcaPemWriter = new JcaPEMWriter(writer);
            jcaPemWriter.writeObject(certificate);
            jcaPemWriter.flush();
            jcaPemWriter.close();
            System.out.println("Certificate written to: " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void storeAttributeCertificate(X509AttributeCertificateHolder holder) {
        try {
            System.out.print("Enter file name:");
            String filename = new Scanner(System.in).nextLine();
            Writer writer = new FileWriter(filename);
            JcaPEMWriter jcaPemWriter = new JcaPEMWriter(writer);
            jcaPemWriter.writeObject(holder);
            jcaPemWriter.flush();
            jcaPemWriter.close();
            System.out.println("AttributeCertificate written to: " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    X509Certificate readCertificate(String fileName) {
        try {

            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(fileName);
            X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
            return certificate;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return null;
    }

    void validateCertificate(String certificateFileName) {
        X509Certificate certificate = readCertificate(certificateFileName);
        if (certificate == null) {
            System.out.println("Could not read the certificate.");
        } else {
            HttpClient client = new DefaultHttpClient();
            try {
                String serializedCertificate = ObjectSerializer.toString(certificate);
                String url = "http://localhost:8080/PMITest_war_exploded/pki/validate/" + serializedCertificate;
                System.out.println("Url: " + url);
                HttpGet get = new HttpGet(url);
                HttpResponse response = client.execute(get);
                printResponse(response, "No validation result returned.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void printResponse(HttpResponse response, String emptyResponseMessage) throws IOException {
        if (response.getEntity() == null) {
            System.out.println(emptyResponseMessage);
        } else {
            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            while ((line = rd.readLine()) != null) {
                System.out.println(line);
            }
        }
    }

    private static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    // Eventually more sense with certificateFileName
    void revokeCertificate(String serialNumber) {
        // TODO: implement revoke
        System.out.println("Is not supported at the moment.");
    }

    void revokeCertificateRequest(String transactionId) {
        // TODO: implement revoke certificate request
        System.out.println("Is not supported at the moment.");
    }

    private X509Certificate convertToCertificate(HttpResponse response) {
        try {
            String content = convertStreamToString(response.getEntity().getContent());
            String serializedCertificate = content.replace("=", "");
            return ObjectDeserializer.fromString(serializedCertificate);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    private X509AttributeCertificateHolder converttoAC(HttpResponse response) {
        try {
            String content = convertStreamToString(response.getEntity().getContent());
            String serializedAC = content.replace("=", "");
            return ObjectDeserializer.fromString(serializedAC);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
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
//BounceCastle Base 64
    public String getFileContent(FileInputStream in) throws FileNotFoundException {
        org.bouncycastle.util.encoders.Base64 bouncy64 = new org.bouncycastle.util.encoders.Base64();
        //read AC local
        in = new FileInputStream("/home/rz/Dokumente/PMIPrototype/ac.pem");
        //FileInputstream umwandeln zu String
        // String pem = getFileContent(in2);
        byte[] data = new byte[0];
        try {
            String pem = getFileContent(in);
            String pemdelimiter = pem.replace("-----BEGIN ATTRIBUTE CERTIFICATE-----", "");
            pemdelimiter = pemdelimiter.replace("-----END ATTRIBUTE CERTIFICATE-----", "");
            pemdelimiter = pemdelimiter.replace("==", "");
            pemdelimiter = pemdelimiter.replaceAll("(?m)^[ \t]*\r?\n", "");
            data = bouncy64.decode(pemdelimiter.getBytes());
            X509AttributeCertificateHolder holder = new X509AttributeCertificateHolder(data);
//            Database myDatabase = new Database();
//            BigInteger acSerial = att.getSerialNumber();
//            BigInteger pkcSerial = att.getHolder().getSerialNumber();
//            //myDatabase.inserting(acSerial,pkcSerial,java.util.Base64.getUrlEncoder().encodeToString(holder.getEncoded()));
//            myDatabase.inserting(acSerial,pkcSerial,null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void createAttributeCertificateRequest(String certificateFilename, String attribute) throws CertificateException, IOException {
        // Read certificate
        //X509Certificate certificate = null;
        X509Certificate certificate = readCertificate(certificateFilename);
        if (certificate == null) {
            System.out.println("No Certificate found.");
        } else {
            //System.out.println(certificate);
        }

        AttributeCertificateRequest request = new AttributeCertificateRequest(certificate, new String[]{attribute});

        HttpClient client = new DefaultHttpClient();
        try {
            String serializedRequest = ObjectSerializer.toString(request);
            String url = "http://localhost:8080/PMITest_war_exploded/pmi/request/create/" + serializedRequest;
            System.out.println("Url: " + url);
            HttpPost post = new HttpPost(url);
            HttpResponse response = client.execute(post);
            // printResponse(response, "No attribute certificate issued.");

            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                builder.append(line);
            }

            Document doc = Jsoup.parse(builder.toString());
            Element link = doc.select("a").first();
            String linkHref = link.attr("href");
            System.out.println(linkHref);

            Pattern pattern = Pattern.compile("AttributeCertificate:([a-zA-Z0-9_-]+)");
            Matcher matcher = pattern.matcher(linkHref);
            if (matcher.find()) {
                // Whole content
                // System.out.println(matcher.group(0));
                String attributeCertificate = matcher.group(1);
                System.out.println("AttributeCertificate: " + attributeCertificate);
                byte[] decoded = ObjectDeserializer.fromString(attributeCertificate);
                X509AttributeCertificateHolder holder = new X509AttributeCertificateHolder(decoded);
                for (int i = 0; i < holder.getAttributes().length; i++) {
                    Attribute attribute1 = holder.getAttributes()[i];
                    RoleSyntax rl = RoleSyntax.getInstance(attribute1.getAttrValues().getObjectAt(i));
                    storeAttributeCertificate(holder);
                    System.out.println("Attribute: " + rl);
                }
            } else {
                System.out.println("Zertifikat konnte nicht erzeugt werden.");
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    void getAttributeCertificate(String serialNumber) throws IOException, ClassNotFoundException {
        X509AttributeCertificateHolder certificateHolder = null;
        try {
            HttpClient client = new DefaultHttpClient();
            String url = "http://localhost:8080/PMITest_war_exploded/pmi/get/" + serialNumber;
            System.out.println("Url: " + url);
            HttpGet get = new HttpGet(url);
            HttpResponse response = client.execute(get);

            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                builder.append(line);
            }

            String ac = new String(builder);

            // Convert to AC object
            byte[] data = Base64.getUrlDecoder().decode(ac);
            certificateHolder = new X509AttributeCertificateHolder(data);
            storeAttributeCertificateDialog(certificateHolder);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    void revokeAttributCertificate(String serialNumber) throws IOException {
        try {
            HttpClient client = new DefaultHttpClient();
            String url = "http://localhost:8080/PMITest_war_exploded/pmi/revoke/" + serialNumber;
            System.out.println("Url: " + url);
            HttpDelete delete = new HttpDelete(url);
            HttpResponse response = client.execute(delete);

            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                builder.append(line);
            }
            System.out.println(builder.toString());
        }catch (IOException e){
            e.printStackTrace();
        }
    }
    public void requestPkcAc(String certificateFilename, String base64ac){
        X509Certificate certificate = readCertificate(certificateFilename);
        if (certificate == null) {
            System.out.println("No Certificate found.");
        } else {
        }
        ValidatePkcAc validatePkcAc = new ValidatePkcAc(certificate, base64ac);

        HttpClient client = new DefaultHttpClient();
        try {
            String serializedRequest = ObjectSerializer.toString(validatePkcAc);
            String url = "http://localhost:8080/PMITest_war_exploded/pmi/validate/" + serializedRequest;
            System.out.println("Url: " + url);
            HttpGet get = new HttpGet(url);
            HttpResponse response = client.execute(get);

            BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                builder.append(line);
            }
            String output = new String(builder);
            System.out.println(output);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
