package org.jboss.pnc.environmentdriver.exceptions;

public class QuotaExceededException extends RuntimeException {

    private static final long serialVersionUID = 351111124411290766L;

    public QuotaExceededException(String message) {
        super(message);
    }

    public QuotaExceededException(String message, Throwable cause) {
        super(message, cause);
    }
}
