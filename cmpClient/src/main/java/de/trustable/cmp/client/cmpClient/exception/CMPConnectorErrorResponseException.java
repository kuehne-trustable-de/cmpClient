package de.trustable.cmp.client.cmpClient.exception;

import java.security.GeneralSecurityException;

public class CMPConnectorErrorResponseException extends GeneralSecurityException {
    public CMPConnectorErrorResponseException(String message) {
        super(message);
    }
}
