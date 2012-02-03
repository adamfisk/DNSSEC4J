package org.littleshoot.dnssec4j;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.littleshoot.dnssec4j.DnsSec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class for creating addresses. This class is DNSSEC-aware, so will attempt
 * to use DNSSEC if configured to do so.
 */
public class VerifiedAddressFactory {
    
    private static final Logger LOG = 
        LoggerFactory.getLogger(VerifiedAddressFactory.class);

    /**
     * Creates a new InetSocketAddress, verifying the host with DNSSEC if 
     * configured to do so.
     * 
     * @param host The host.
     * @param port The port.
     * @return The endpoint.
     */
    public static InetSocketAddress newInetSocketAddress(final String host, 
        final int port) {
        return newInetSocketAddress(host, port, true);
    }
    
    /**
     * Creates a new InetSocketAddress, verifying the host with DNSSEC if 
     * configured to do so.
     * 
     * @param host The host.
     * @param port The port.
     * @param useDnsSec Whether or not to use DNSSEC.
     * @return The endpoint.
     */
    public static InetSocketAddress newInetSocketAddress(final String host, 
        final int port, final boolean useDnsSec) {
        if (useDnsSec) {
            try {
                final InetAddress verifiedHost = DnsSec.getByName(host);
                return new InetSocketAddress(verifiedHost, port);
            } catch (final IOException e) {
                LOG.info("Could not resolve address for: "+host, e);
            } catch (final DNSSECException e) {
                LOG.warn("DNSSEC error. Bad signature?", e);
                throw new Error("DNSSEC error. Bad signature?", e);
            }
        }
        return new InetSocketAddress(host, port);
    }

}
