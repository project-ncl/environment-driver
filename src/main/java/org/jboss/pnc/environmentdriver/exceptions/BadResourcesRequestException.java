package org.jboss.pnc.environmentdriver.exceptions;

public class BadResourcesRequestException extends RuntimeException {

    private static final long serialVersionUID = 4098171178739096610L;

    public BadResourcesRequestException(String message) {
        super(message);
    }

    public BadResourcesRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
