package org.littleshoot.dnssec4j;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;


public class DnsSecTest {

    @Test public void testDnsSec() throws Exception {
        final Record [] records = new Lookup("gmail.com", Type.A).run();
        for (final Record record : records) {
            //final MXRecord mx = (MXRecord) records[i];
            //System.out.println("Host " + mx.getTarget() + " has preference " + mx.getPriority());
            //System.out.println("REC: "+record.getName()+" "+record+" "+record.getType());
            //System.out.println(record);
        }
        
        final Name zone = Name.fromString("gmail.com.");
        final Name host = Name.fromString("host", zone);
        //Update update = new Update(zone);
        //update.replace(host, Type.A, 3600, args[0]);

        Resolver res = new SimpleResolver("8.8.4.4");
        //res.setTSIGKey(new TSIG(host, base64.fromString("1234")));
        res.setTCP(true);

        //final Message response = res.send(update);

        Record question = Record.newRecord(zone, Type.A, DClass.IN);
        Message query = Message.newQuery(question);
        Message response = null;
        try {
            response = res.send(query);
            System.out.println("**********\n"+response);
            final RRset[] rr = response.getSectionRRsets(0);
            for (final RRset set : rr) {
                System.out.println("RR1: "+set);
            }
            final RRset[] rr1 = response.getSectionRRsets(1);
            for (final RRset set : rr1) {
                System.out.println("RR2: "+set);
            }
            final RRset[] rr2 = response.getSectionRRsets(2);
            for (final RRset set : rr2) {
                System.out.println("RR3: "+set);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            // A network error occurred.  Press on.
            /*
            if (e instanceof InterruptedIOException)
                timedout = true;
            else
                networkerror = true;
            return;
            */
        }
    }
}
