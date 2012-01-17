package org.littleshoot.dnssec4j;

import static org.junit.Assert.assertEquals;

import java.net.InetAddress;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DnsSecTest {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    @Test
    public void testGetByName() throws Exception {
        final InetAddress ia = DnsSec.getByName("www.verisign.com");
        //final InetAddress ia = InetAddress.getByName("www.google.com");
        log.info("Resolved address: "+ia);
        
        assertEquals("69.58.181.89", ia.getHostAddress());
    }
}
