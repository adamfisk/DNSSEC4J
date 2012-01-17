package org.littleshoot.dnssec4j;

import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Options;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;


public class DnsSecTest {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    {
    //System.setProperty("sun.net.spi.nameservice.nameservers", "8.8.8.8,8.8.4.4");
    //System.setProperty("sun.net.spi.nameservice.nameservers", "75.75.75.75 ,75.75.75.76");
        
    // These are from https://www.dns-oarc.net/oarc/services/odvr
    System.setProperty("sun.net.spi.nameservice.nameservers", "149.20.64.20,149.20.64.21");
    }
    
    @Test
    public void testDNSKEYLookup() throws Exception {
        final String site = "www.verisign.com";
        final Name name = Name.fromString(site);
        final Name full = Name.concatenate(name, Name.root);
        verifyFullRecord(full);
    }

    private void verifyFullRecord(final Name full) throws IOException, 
        DNSSECException {
        System.out.println("Verifying record: "+ full);
        final String [] servers = ResolverConfig.getCurrentConfig().servers();
        System.out.println(Arrays.asList(servers));
        final Resolver res = new ExtendedResolver();
        res.setEDNS(0, 0, ExtendedFlags.DO, null);
        res.setTCP(true);
        res.setTimeout(40);
        final Record question = Record.newRecord(full, Type.A, DClass.IN);
        final Message query = Message.newQuery(question);
        final Message response = res.send(query);
        System.out.println("RESPONSE: "+response);
        final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        
        //System.out.println("Answers: "+Arrays.asList(answer));
        // TODO: Verify all sets!
        for (final RRset set : answer) {
        //for (int i = 0; i < 1; i++) {
            //final RRset set = answer[i];
            System.out.println("\n;; RRset to chase:");
            //System.out.println(set);
            final Iterator<Record> rrIter = set.rrs();
            while (rrIter.hasNext()) {
                final Record rec = rrIter.next();
                System.out.println(rec);
            }
            final Iterator<Record> sigIter = set.sigs();
            //if (!sigIter.hasNext()) {
            //    throw new IOException("No sig records?");
            //}
            //RRSIGRecord rec = null;
            while (sigIter.hasNext()) {
                final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                System.out.println("\n;; RRSIG of the RRset to chase:");
                System.out.println(rec);
                verifyZone(set, rec);
            }
        }
    }

    private void verifyZone(final RRset set, final RRSIGRecord record) 
        throws IOException, DNSSECException {
        System.out.println("\nLaunch a query to find a RRset of type DNSKEY for zone: "+record.getSigner());

        //System.out.println("\nVerifying sig for rec: "+record);
        //final DNSKEYRecord publicKey = signingKeyForRecord (record);
        
        final Name signer = record.getSigner();
        final int tag = record.getFootprint();
        System.out.println("Looking for tag: "+tag);
        
        boolean keyVerified = false;
        DNSKEYRecord keyRec = null;
        RRset recursiveSet = null;
        RRSIGRecord recursiveSig = null;
        
        // We need to perform a multiline query to get the tags associated with
        // keys, which lets us verify records with the correct key.
        try {
            Options.set("multiline");
            final Resolver res = new ExtendedResolver();
            res.setEDNS(0, 0, ExtendedFlags.DO, null);
            res.setTCP(true);
            
            // Timeouts are in seconds.
            res.setTimeout(40);
            
            final Record question = Record.newRecord(signer, Type.DNSKEY, DClass.IN);
            final Message query = Message.newQuery(question);
            final Message response = res.send(query);
            
            final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
            for (final RRset answerSet : answer) {
                System.out.println("\n;; DNSKEYset that signs the RRset to chase:");
                //System.out.println(set);
                final Iterator<Record> rrIter = answerSet.rrs();
                while (rrIter.hasNext()) {
                    final Record rec = rrIter.next();
                    System.out.println(rec);
                    if (rec instanceof DNSKEYRecord) {
                        final DNSKEYRecord dnskKeyRec = (DNSKEYRecord) rec;
                        if (dnskKeyRec.getFootprint() == tag) {
                            System.out.println("\n\nFound matching DNSKEY for tag!! "+tag+"\n\n");
                            keyRec = dnskKeyRec;
                        }
                    }
                }
                System.out.println("\n;; RRSIG of the DNSKEYset that signs the RRset to chase:");
                final Iterator<Record> sigIter = answerSet.sigs();
                while (sigIter.hasNext()) {
                    final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                    System.out.println(rec);
                    
                    // This resource record set will be self-signed. Verify
                    // the signature as we go, and we'll validate the DS record
                    // as well later.
                    if (rec.getFootprint() == tag) {
                        System.out.println("Found matching footprint/tag!! "+tag);
                        DNSSEC.verify(answerSet, rec, keyRec);
                        keyVerified = true;
                        recursiveSet = answerSet;
                        recursiveSig = rec;
                    }
                }
            }
            if (!keyVerified) {
                System.out.println("KEY NOT VERIFIED!!");
                //throw new IOException("Key not verified!!");
            }
            if (keyRec == null) {
                throw new IOException("Did not find DNSKEY record matching tag: "+tag);
            }
            //return keyRec;
        } finally {
            Options.unset("multiline");
        }
        DNSSEC.verify(set, record, keyRec);
        
        verifyDsRecordForSignerOf(record);
    }

    private DNSKEYRecord verifySig(final RRset set, final RRSIGRecord rrsig) 
        throws IOException, DNSSECException {
        //System.out.println("FOOTPRINT: " + rrsig.getFootprint());
        final DNSKEYRecord publicKey = signingKeyForRecord (rrsig);
        DNSSEC.verify(set, rrsig, publicKey);
        return publicKey;
    }

    private DNSKEYRecord signingKeyForRecord(final RRSIGRecord record) 
        throws IOException, DNSSECException {
        final Name signer = record.getSigner();
        final int tag = record.getFootprint();
        
        boolean keyVerified = false;
        // We need to perform a multiline query to get the tags associated with
        // keys, which lets us verify records with the correct key.
        try {
            Options.set("multiline");
            final Resolver res = new ExtendedResolver();
            res.setEDNS(0, 0, ExtendedFlags.DO, null);
            res.setTCP(true);
            
            // Timeouts are in seconds.
            res.setTimeout(40);
            
            final Record question = Record.newRecord(signer, Type.DNSKEY, DClass.IN);
            final Message query = Message.newQuery(question);
            final Message response = res.send(query);
            
            final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
            DNSKEYRecord keyRec = null;
            for (final RRset set : answer) {
                System.out.println("\n;; DNSKEYset that signs the RRset to chase:");
                //System.out.println(set);
                final Iterator<Record> rrIter = set.rrs();
                while (rrIter.hasNext()) {
                    final Record rec = rrIter.next();
                    System.out.println(rec);
                    if (rec instanceof DNSKEYRecord) {
                        final DNSKEYRecord dnskKeyRec = (DNSKEYRecord) rec;
                        if (dnskKeyRec.getFootprint() == tag) {
                            keyRec = dnskKeyRec;
                        }
                    }
                }
                System.out.println("\n;; RRSIG of the DNSKEYset that signs the RRset to chase:");
                final Iterator<Record> sigIter = set.sigs();
                while (sigIter.hasNext()) {
                    final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                    System.out.println(rec);
                    
                    // This resource record set will be self-signed. Verify
                    // the signature as we go, and we'll validate the DS record
                    // as well later.
                    if (rec.getFootprint() == tag) {
                        DNSSEC.verify(set, rec, keyRec);
                        keyVerified = true;
                    }
                }
            }
            if (!keyVerified) {
                throw new IOException("Key not verified!!");
            }
            if (keyRec == null) {
                throw new IOException("Did not find DNSKEY record matching tag: "+tag);
            }
            return keyRec;
        } finally {
            Options.unset("multiline");
        }
    }
    

    private void verifyDsRecordForSignerOf(final RRSIGRecord rec) 
        throws IOException, DNSSECException {
        final Name signer = rec.getSigner();
        System.out.println("\nLaunch a query to find a RRset of type DS for zone: "+signer);
        final Resolver res = new ExtendedResolver();
        res.setEDNS(0, 0, ExtendedFlags.DO, null);
        res.setTCP(true);
        
        // Timeouts are in seconds.
        res.setTimeout(40);
        
        final Record question = Record.newRecord(signer, Type.DS, DClass.IN);
        final Message query = Message.newQuery(question);
        final Message response = res.send(query);
        System.out.println("DS RESPONSE:\n**************\n"+response+"\n**************\n");
        
        final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        for (final RRset set : answer) {
            //System.out.println(set);
            final Iterator<Record> rrIter = set.rrs();
            System.out.println("\n;; DSset of the DNSKEYset");
            while (rrIter.hasNext()) {
                System.out.println(rrIter.next());
            }
            final Iterator<Record> sigIter = set.sigs();
            System.out.println("\n;; RRSIG of the DSset of the DNSKEYset");
            while (sigIter.hasNext()) {
                final Record sigRec = sigIter.next();
                System.out.println(sigRec);
                if (sigIter.hasNext()) {
                    throw new IOException("We don't handle more than one RRSIGRecord for DS responses!!");
                }
                if (sigRec instanceof RRSIGRecord) {
                    final RRSIGRecord rr = (RRSIGRecord) sigRec;
                    
                    //System.out.println("VERIFYING DS RECORD -- RECURSIVE CALL!!");
                    System.out.println(";; Now, we want to validate the DS :  recursive call");
                    verifyZone(set, rr);
                    //System.out.println("\n;; Verifying signature of DS record");
                    //verifySig(set, rr);
                } else {
                    //System.out.println("non-sig record");
                    //System.out.println(sigRec);
                }
            }
        }
        
        System.out.println(";; Out of recursive call");
    }

    private DNSKEYRecord getRootKey() throws DNSSECException, IOException {
        final Resolver res = new ExtendedResolver();
        res.setEDNS(0, 0, ExtendedFlags.DO, null);
        res.setTCP(true);
        res.setTimeout(40);
        
        //final String site = "www.verisign.com";
        //final Name name = Name.fromString(site);
        //final Name full = Name.concatenate(name, Name.root);
        final Name full = Name.root;
        final Record question = Record.newRecord(full, Type.DNSKEY, DClass.IN);

        
        final Message query = Message.newQuery(question);
        
        final Message response = res.send(query);
        //DNSKEYRecord rec = 
        //    new DNSKEYRecord(full, question.getDClass(), question.getTTL(), 0, question.g, alg, key)
        System.out.println("RESPONSE: "+response);
        System.out.println("RESPONSE: "+response.getQuestion().getClass());
        
        printSet(response);
        
        final RRset answer = response.getSectionRRsets(Section.ANSWER)[0];
        final RRSIGRecord rrsig = rrsig(answer);
        final DNSKEYRecord publicKey = publicKey(answer);
        DNSSEC.verify(answer, rrsig, publicKey);
        return publicKey;
    }


    private DNSKEYRecord publicKey(final RRset set) throws IOException {
        final Iterator<Record> iter = set.rrs();
        while (iter.hasNext()) {
            final Record rec = iter.next();
            System.out.println("record rdataToString: "+rec.rdataToString());
            System.out.println("Class: "+rec.getClass());
            //System.out.println("Footprint: "+rec.getFootprint());
            if (rec instanceof DNSKEYRecord) {
                return (DNSKEYRecord) rec;
            }
        }
        throw new IOException("No public key in rr set: "+set);
    }


    private RRSIGRecord rrsig(final RRset set) throws IOException {

        
        final Iterator<RRSIGRecord> sigs = set.sigs();
        while (sigs.hasNext()) {
            final RRSIGRecord rec = sigs.next();
            System.out.println("sig record rdataToString: "+rec.rdataToString());
            System.out.println("Class: "+rec.getClass());
            if (sigs.hasNext()) {
                //throw new IOException("How should we handle multiple RRSIGRecords?");
            }
            return rec;
        }
        throw new IOException("No RRSIGRecord in set: " + set);
    }


    public void testSimpleResolver() throws Exception {
        final Resolver res = new ExtendedResolver();
        res.setEDNS(0, 0, ExtendedFlags.DO, null);
        res.setTCP(true);
        res.setTimeout(40);
        
        final String site = "www.verisign.com";
        final Name name = Name.fromString(site);
        //final Name full = Name.concatenate(name, Name.root);
        final Name full = Name.root;
        final Record question = Record.newRecord(full, Type.A, DClass.IN);
        final Message query = Message.newQuery(question);
        
        final Message response = res.send(query);
        System.out.println("RESPONSE: "+response);
        printSet(response);
    }
    
    private void printSet(final Message response) {
        final RRset[] rrsets = response.getSectionRRsets(Section.ANSWER);
        System.out.println("# SETS: "+rrsets.length);
        for (final RRset set : rrsets) {
            System.out.println("SET: "+set);
            final Iterator<Record> iter = set.rrs();
            while (iter.hasNext()) {
                final Record rec = iter.next();
                System.out.println(rec);
                //System.out.println("rec: "+rec.rdataToString());
                //System.out.println("Class: "+rec.getClass());
                //System.out.println("Footprint: "+rec.getFootprint());
            }
            
            final Iterator<Record> sigs = set.sigs();
            while (sigs.hasNext()) {
                final Record rec = sigs.next();
                System.out.println(rec);
                //System.out.println("sig record rdataToString: "+rec.rdataToString());
                //System.out.println("Class: "+rec.getClass());
            }
        }
    }

    public void testDnsSec() throws Exception {
        final String site = "www.verisign.com";
        final Record [] records = new Lookup(site, Type.A).run();
        for (final Record record : records) {
            //final MXRecord mx = (MXRecord) records[i];
            //System.out.println("Host " + mx.getTarget() + " has preference " + mx.getPriority());
            //System.out.println("REC: "+record.getName()+" "+record+" "+record.getType());
            //System.out.println(record);
        }
        
        final Name zone = Name.fromString(site + ".");
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
