package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.RemoteTargetHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

public class SimpleRemoteTargetHandler implements RemoteTargetHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleRemoteTargetHandler.class);

    /**
     * make a remote http call
     *
     * @param requestUrl the target of the call
     * @param requestBytes the bytes to be send
     * @return the received bytes
     * @throws IOException io handling went wrong
     */
    public byte[] sendHttpReq(final String requestUrl,
                              final byte[] requestBytes,
                              final String contentType,
                              final String sni,
                              final boolean disableHostNameVerifier,
                              final KeyStore keyStore,
                              final String keyPassword) throws IOException, GeneralSecurityException {

        LOGGER.debug("Sending request to: " + requestUrl);

        long startTime = System.currentTimeMillis();

        URL url = new URL(requestUrl);

        HttpURLConnection con;

        if( "https".equalsIgnoreCase(url.getProtocol())) {

            LOGGER.debug("sending message to TLS endpoint");

            if( sni != null){
                LOGGER.warn("sni not supported!");
            }
            try {
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                SSLContext context = SSLContext.getInstance("TLS");
                if( keyStore != null) {
                    LOGGER.debug("using client keystore");
                    keyManagerFactory.init(keyStore, keyPassword.toCharArray());

                    context.init(
                            keyManagerFactory.getKeyManagers(),
                            null,
                            new SecureRandom()
                    );
                }else{
                    context.init(
                            null,
                            null,
                            new SecureRandom());
                }

                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setSSLSocketFactory(context.getSocketFactory());
                con = conn;
            } catch(Exception ex){
                throw new GeneralSecurityException(ex);
            }
        }else {
            con = (HttpURLConnection) url.openConnection();
        }

        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        if( contentType != null && !contentType.isEmpty()) {
            con.setRequestProperty("Content-Type", contentType);
        }

        java.io.OutputStream os = con.getOutputStream();
        os.write(requestBytes);
        os.close();

        // Read the response
        InputStream in = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            in = con.getInputStream();

            byte[] tmpBA = new byte[8192];
            int nBytes;
            while ((nBytes = in.read(tmpBA)) > 0) {
                baos.write(tmpBA, 0, nBytes);
            }
            LOGGER.debug("# " + baos.size() + " response bytes received");
        } finally {
            if (in != null) {
                in.close();
            }
        }

        if (con.getResponseCode() == 200) {
            LOGGER.debug("Received certificate reply.");
        } else {
            throw new IOException("Error sending CMP request. Response code != 200 : " + con.getResponseCode());
        }

        // We are done, disconnect
        con.disconnect();

        LOGGER.debug("duration of remote CMP call " + (System.currentTimeMillis() - startTime));

        return baos.toByteArray();
    }

}
