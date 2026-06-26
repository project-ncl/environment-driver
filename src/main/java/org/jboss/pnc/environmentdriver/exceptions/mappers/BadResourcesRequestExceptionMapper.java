package org.jboss.pnc.environmentdriver.exceptions.mappers;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.jboss.pnc.api.dto.ErrorResponse;
import org.jboss.pnc.environmentdriver.exceptions.BadResourcesRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class BadResourcesRequestExceptionMapper implements ExceptionMapper<BadResourcesRequestException> {

    private static final Logger logger = LoggerFactory.getLogger(BadResourcesRequestExceptionMapper.class);

    @Override
    public Response toResponse(BadResourcesRequestException e) {
        logger.error("An exception occurred while parsing either the service or the pod templates", e);

        Response.ResponseBuilder builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode());
        builder.entity(new ErrorResponse(e)).type(MediaType.APPLICATION_JSON);

        return builder.build();
    }

}
