DNSSEC4J is a java library that utilizes the DNSSEC primitives in dnsjava to allow users to automatically request extended flags in DNS lookups and to verify the signatures on records when they exist. It is licensed under both the Apache 2 and GNU General Public License version 3. Users of this software may utilize it under either license.

DNSSEC4J is made possible through the generous contributions of the NLNet Foundation. They have helped make many projects possible, including NoScript and Tor. Please donate to them if you can at:

http://nlnet.nl/donating/

To integrate DNSSEC4J in your projects, you can use a maven dependency as follows:

```
    <dependency>
        <groupId>org.littleshoot</groupId>
        <artifactId>dnssec4j</artifactId>
        <version>0.1-SNAPSHOT</version>
    </dependency>
```

You will also need to integrate the Sonatype Maven repositories. You really only need the snapshot repository at this time, but you will need the releases repository when DNSSEC4J goes final.

```
        <repository>
            <id>sonatype-nexus-snapshots</id>
            <name>Sonatype Nexus Snapshots</name>
            <url>https://oss.sonatype.org/content/repositories/snapshots</url>
            <releases>
                <enabled>false</enabled>
            </releases>
            <snapshots>
                <enabled>true</enabled>
            </snapshots>
        </repository>

        <repository>
            <id>sonatype-nexus-releases</id>
            <name>Sonatype Nexus Snapshots</name>
            <url>https://oss.sonatype.org/content/repositories/releases</url>
            <releases>
                <enabled>true</enabled>
            </releases>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
```

DNSSEC4J provides several convenience classes for easily integrating DNSSEC into your projects. For example, the VerifiedSocketFactory class wraps an existing SocketFactory and resolves and verifies host names before passing them along to the real SocketFactory implementation. The VerifiedAddressFactory does something similar with InetAddresses and InetSocketAddresses, allowing callers to easily create versions of those classes with the host names resolved and verified.

To create a VerifiedSocketFactory you can do, for example:

```
    new VerifiedSocketFactory(SocketFactory.getDefault());
```

To create an InetSocketAddress with the host name verified, you can do:

```
    final InetSocketAddress isa = VerifiedAddressFactory.newInetSocketAddress("www.verisign.com", 80);
```

*DNSSEC4J is still in its infancy and requires more thorough testing and review within the security community. It should be considered experimental and not ready for production use at this time.*

