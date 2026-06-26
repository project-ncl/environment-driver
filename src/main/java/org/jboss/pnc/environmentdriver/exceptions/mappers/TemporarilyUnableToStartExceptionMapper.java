package org.jboss.pnc.environmentdriver.exceptions.mappers;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.jboss.pnc.api.dto.ErrorResponse;
import org.jboss.pnc.environmentdriver.exceptions.TemporarilyUnableToStartException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class TemporarilyUnableToStartExceptionMapper implements ExceptionMapper<TemporarilyUnableToStartException> {

    private static final Logger logger = LoggerFactory.getLogger(TemporarilyUnableToStartExceptionMapper.class);

    @Override
    public Response toResponse(TemporarilyUnableToStartException e) {
        logger.error("A temporarily exception occurred while starting the pod", e);

        Response.ResponseBuilder builder = Response.status(Response.Status.SERVICE_UNAVAILABLE.getStatusCode());
        builder.entity(new ErrorResponse(e)).type(MediaType.APPLICATION_JSON);

        return builder.build();
    }

}
