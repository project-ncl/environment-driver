/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.pnc.environmentdriver.endpoints;

import io.quarkus.security.Authenticated;
import org.jboss.pnc.environmentdriver.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.concurrent.CompletionStage;

/**
 *
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class Public {

    private static final Logger logger = LoggerFactory.getLogger(Public.class);

    @Inject
    Driver driver;

    /**
     * Create new build environment for a given configuration.
     */
    @Authenticated
    @POST
    @Path("/build")
    public CompletionStage<CreateResponse> create(CreateRequest createRequest) {
        logger.info("Requested new environment: {}", buildRequest.getProjectName());
        return driver.create(createRequest);
    }

    @Authenticated
    @PUT
    @Path("/destroy")
    public CompletionStage<Response> destroy(DestroyRequest destroyRequest) {
        logger.info("Requested environment destroy: {}", cancelRequest.getBuildExecutionId());
        return driver.destroy(destroyRequest).thenApply((r) -> Response.status(r.getCode()).build());
    }
}
