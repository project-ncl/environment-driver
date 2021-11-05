package org.jboss.pnc.environmentdriver.exceptions.mappers;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.jboss.pnc.api.dto.ErrorResponse;
import org.jboss.pnc.environmentdriver.exceptions.QuotaExceededException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class QuotaExceededExceptionMapper implements ExceptionMapper<QuotaExceededException> {

    private static final Logger logger = LoggerFactory.getLogger(QuotaExceededExceptionMapper.class);

    @Override
    public Response toResponse(QuotaExceededException e) {
        logger.error("An exception occurred due to exceeded quota", e);

        Response.ResponseBuilder builder = Response.status(Response.Status.SERVICE_UNAVAILABLE.getStatusCode());
        builder.entity(new ErrorResponse(e)).type(MediaType.APPLICATION_JSON);

        return builder.build();
    }

}
