import com.serialization.ObjectDeserializer;
import com.serialization.ObjectSerializer;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.transaction.TransactionId;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 04.05.17.
 */

@Path("pki")
public class PKIService {

    private final PKIManagement pki;

    public PKIService() throws OperatorCreationException, MalformedURLException, NoSuchAlgorithmException, CertificateException {
        pki = new PKIManagement();
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
    public void createRequest(@PathParam("request") String request, @Context HttpServletResponse servletResponse) throws IOException {
        String redirectUrl = "../../status/";

        try {
            PKCS10CertificationRequest csr = ObjectDeserializer.fromCSRString(request);
            EnrollmentResponse res = pki.enrol(csr);

            TransactionId transactionId = res.getTransactionId();
            String serializeId = ObjectSerializer.toString(transactionId);
            String serializedSubject = ObjectSerializer.toString(pki.getSubject());

            redirectUrl += "Success:"  + res.isSuccess()
                    + "_Pending:" + res.isPending()
                    + "_Failure:" + res.isFailure()
                    + "_TransId:" + serializeId
                    + "_Subject:" + serializedSubject;
        } catch (Exception e) {
            e.printStackTrace();
            redirectUrl += e.getMessage();
        }

        servletResponse.sendRedirect(redirectUrl);
    }

    /**
     * Difference to poll is that poll is used with the transaction id, not with serial number
     */
    @GET
    @Path("get/{serialNumber}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String get(@PathParam("serialNumber") String serialNumber) throws IOException {
        // Test: http://localhost:8080/PMITest_war_exploded/pki/get/5208e918c6dc96a6d6ff
        BigInteger parsedSerialNumber = new BigInteger(serialNumber, 16);
        X509Certificate certificate = pki.getCertificate(parsedSerialNumber);
        return certificate == null ? "No certificate found" : ObjectSerializer.toString(certificate);

        //Methodenaufruf getSerialNumber aus Datenbank Object, übergabe der SerialNumber vom Client Wert
    }

    @GET
    @Path("poll/{principal}/{transactionId}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String poll(@PathParam("principal") String principal, @PathParam("transactionId") String transactionId) throws IOException, ClassNotFoundException {
        X500Principal parsedPrincipal = ObjectDeserializer.fromString(principal);
        TransactionId parsedTransactionId = ObjectDeserializer.fromString(transactionId);
        X509Certificate certificate =  pki.pollCertificate(parsedPrincipal, parsedTransactionId);
        return certificate == null ? "No certificate found" : ObjectSerializer.toString(certificate);
    }

    @DELETE
    @Path("revoke/{serialNumber}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void revoke(@PathParam("serialNumber") String serialNumber) {
        // TODO: email to administrator
    }

    @GET
    @Path("validate/{pkc}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String validate(@PathParam("pkc") String pkc) throws IOException, ClassNotFoundException, ClientException {
        X509Certificate certificate = ObjectDeserializer.fromString(pkc);
        return pki.validateCertificate(certificate);
    }
}