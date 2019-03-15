package validation;

/**
 * This class wraps an exception that could be thrown during
 * the certificate verification process.
 *
 * @author Svetlin Nakov
 */
public class CertificateValidationException extends Exception {
    private static final long serialVersionUID = 1L;

    public CertificateValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateValidationException(String message) {
        super(message);
    }
}