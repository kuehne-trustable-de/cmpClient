package de.trustable.cmp.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

public interface RemoteTargetHandler {
    byte[] sendHttpReq(final String requestTarget,
                              final byte[] requestBytes,
                              final KeyStore KeyStore,
                              final String keyPassword) throws IOException, GeneralSecurityException;
}
