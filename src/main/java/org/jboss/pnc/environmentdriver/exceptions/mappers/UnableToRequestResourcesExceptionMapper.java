package org.jboss.pnc.environmentdriver.exceptions.mappers;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.jboss.pnc.api.dto.ErrorResponse;
import org.jboss.pnc.environmentdriver.exceptions.UnableToRequestResourcesException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class UnableToRequestResourcesExceptionMapper implements ExceptionMapper<UnableToRequestResourcesException> {

    private static final Logger logger = LoggerFactory.getLogger(UnableToRequestResourcesExceptionMapper.class);

    @Override
    public Response toResponse(UnableToRequestResourcesException e) {
        logger.error("An exception occurred while requesting resources", e);

        Response.ResponseBuilder builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode());
        builder.entity(new ErrorResponse(e)).type(MediaType.APPLICATION_JSON);

        return builder.build();
    }

}
