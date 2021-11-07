package org.jboss.pnc.environmentdriver.exceptions;

public class TemporarilyUnableToStartException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TemporarilyUnableToStartException(String message) {
        super(message);
    }

    public TemporarilyUnableToStartException(String message, Throwable cause) {
        super(message, cause);
    }
}