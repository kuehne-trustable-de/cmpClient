package de.trustable.cmp.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;

import java.security.GeneralSecurityException;

public interface ProtectedMessageHandler {

    ProtectedPKIMessage signMessage(final ProtectedPKIMessageBuilder builder) throws GeneralSecurityException;

    boolean verifyMessage(final ProtectedPKIMessage message) throws GeneralSecurityException;

    X500Name getSender( X500Name subjectDN);

    void addCertificate( ProtectedPKIMessageBuilder pbuilder);

}
