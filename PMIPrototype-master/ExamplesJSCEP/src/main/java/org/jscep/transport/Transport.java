package org.jscep.transport;

import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

public interface Transport {
    /**
     * Sends the provided request to the <tt>URL</tt> provided in the
     * constructor.
     * <p>
     * This method will use the provided <tt>ScepResponseHandler</tt> to parse
     * the SCEP server response. If the response can be correctly parsed, this
     * method will return the response. Otherwise, this method will throw a
     * <tt>TransportException</tt>
     *
     * @param <T>
     *            the response type.
     * @param msg
     *            the message to send.
     * @param handler
     *            the handler used to parse the response.
     * @return the SCEP server response.
     * @throws org.jscep.transport.TransportException
     *             if any transport error occurs.
     */
    <T> T sendRequest(Request msg,
                      ScepResponseHandler<T> handler) throws TransportException;
}
