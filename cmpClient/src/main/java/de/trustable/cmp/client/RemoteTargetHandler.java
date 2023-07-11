package de.trustable.cmp.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

public interface RemoteTargetHandler {
    byte[] sendHttpReq(final String requestTarget,
                       final byte[] requestBytes,
                       final String contentType,
                       final String sni,
                       final boolean disableHostNameVerifier,
                       final KeyStore KeyStore,
                       final String keyPassword) throws IOException, GeneralSecurityException;
}
