import com.serialization.AttributeCertificateRequest;
import com.serialization.ObjectDeserializer;
import com.serialization.ObjectSerializer;
import com.serialization.ValidatePkcAc;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.jscep.client.ClientException;
import com.mysql.jdbc.Driver;

import javax.naming.NamingException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.awt.*;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;

@Path("pmi")
public class PMIService {

    private final PMIManagement pmi;
    Database database = new Database();
    PKIManagement pki = new PKIManagement();
    public PMIService() throws SQLException, ClassNotFoundException, OperatorCreationException, MalformedURLException, NoSuchAlgorithmException, CertificateException {
        pmi = new PMIManagement();
    }

    @GET
    @Path("status/{message}")
    @Produces(MediaType.TEXT_HTML)
    @Consumes(MediaType.TEXT_PLAIN)
    public String status(@PathParam("message") String message) {
        return message;
    }

    @POST
    @Path("request/create/{request}")
    @Consumes(MediaType.TEXT_PLAIN)
    public void createRequest(@PathParam("request") String request, @Context HttpServletResponse servletResponse) throws Exception {
        String redirectUrl = "../../status/";
        AttributeCertificateRequest parsedRequest = ObjectDeserializer.fromString(request);
        //for (String attribute : parsedRequest.getAttributes()) {
        //    redirectUrl += "\nAttribute: " + attribute;
        //}
        X509Certificate clientcert = parsedRequest.getCertificate();
        //redirectUrl += "\nSerialnumber: " + clientcert.getSerialNumber().toString() + "\nIssuer: " + clientcert.getIssuerX500Principal().toString() + "\nSubject: " + clientcert.getSubjectDN().toString();

        X509AttributeCertificateHolder holder = pmi.createAttributeCertificate(parsedRequest);

        if (holder == null){
            throw new UnsupportedOperationException("Kein Attribut-Zertifikat");
        }


        byte [] holder_encoded = holder.getEncoded();
        //String ac = Base64.getUrlEncoder().encodeToString(att.getEncoded());

        String encoded = ObjectSerializer.toString(holder_encoded);//Base64.getUrlEncoder().encodeToString(holder_encoded);

        //String newString = new String(encoded);

        redirectUrl += "AttributeCertificate:" + encoded;


        servletResponse.sendRedirect(redirectUrl);

    }

    //getac

    @GET
    @Path("get/{serialNumber}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String get(@PathParam("serialNumber") String serialNumber) throws IOException, NamingException {

        BigInteger serialNumber_ = new BigInteger(serialNumber);
        String redirectUrl = database.getSerialNumber(serialNumber_);

        return redirectUrl;
    }

    @GET
    @Path("poll/{transactionId}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String poll(@PathParam("transactionId") String transactionId) {
        // TODO: implement poll
        return "Not supported at the moment.";
    }

    @DELETE
    @Path("revoke/{serialNumber}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String revoke(@PathParam("serialNumber") String serialNumber) throws IOException, NamingException, SQLException {
        BigInteger serialNumber_ = new BigInteger(serialNumber);
        String result = database.revokeCertificate(serialNumber_);
        return result;
    }

    @GET
    @Path("validate/{validatePkcAc}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String validate(@PathParam("validatePkcAc") String requestpkcac) throws Exception {
        ValidatePkcAc parsedRequest = ObjectDeserializer.fromString(requestpkcac);
        X509Certificate clientcert = parsedRequest.getCertificate();
        String base64ac = parsedRequest.getAcertificate();
         return pmi.requestPkcAc(parsedRequest);
    }
}
