package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.operator.MacCalculator;

import java.security.GeneralSecurityException;

class DigestSigner implements ProtectedMessageHandler {

    final private String hmacSecret;

    public DigestSigner(String hmacSecret1) {
        this.hmacSecret = hmacSecret1;
    }

    @Override
    public ProtectedPKIMessage signMessage(ProtectedPKIMessageBuilder builder) throws GeneralSecurityException {
        System.out.println("in DigestSigner.signMessage ...");
        try {
            MacCalculator macCalculator = CMPClient.getMacCalculator(hmacSecret);
            return builder.build(macCalculator);
        } catch (CRMFException | CMPException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public boolean verifyMessage(ProtectedPKIMessage message) throws GeneralSecurityException {
        System.out.println("in DigestSigner.verifyMessage ...");

        if (!message.hasPasswordBasedMacProtection()) {
            throw new GeneralSecurityException("HMAC secret present, bt server did NOT use MacProtection!");
        }

        try {
            return message.verify(CMPClient.getMacCalculatorBuilder(), hmacSecret.toCharArray());
        } catch (CMPException | CRMFException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public X500Name getSender(X500Name subjectDN) {
        return subjectDN;
    }

    @Override
    public void addCertificate(ProtectedPKIMessageBuilder pbuilder) {
        // nothing to do ...
    }

}
