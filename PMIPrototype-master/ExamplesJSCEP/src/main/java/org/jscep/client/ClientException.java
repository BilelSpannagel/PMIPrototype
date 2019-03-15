package org.jscep.client;

/**
 * This <tt>Exception</tt> occurs when a problem is encountered performing a
 * client request.
 */
public class ClientException extends Exception {
    /**
     * Serialization ID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new <tt>ClientException</tt> with the given cause.
     * 
     * @param cause
     *            the cause of this exception.
     */
    public ClientException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new <tt>ClientException</tt> with the given message.
     * 
     * @param message
     *            a description of the error condition.
     */
    public ClientException(final String message) {
        super(message);
    }
}
