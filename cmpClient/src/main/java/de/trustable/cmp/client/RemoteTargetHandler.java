package de.trustable.cmp.client;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

public interface RemoteTargetHandler {
    byte[] sendHttpReq(final String requestTarget,
                              final byte[] requestBytes,
                              final InputStream getP12ClientStore,
                              final String keyPassword) throws IOException, GeneralSecurityException;
}
