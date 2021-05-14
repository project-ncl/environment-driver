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

import java.util.concurrent.CompletionStage;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import io.quarkus.security.Authenticated;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCompleteRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCompleteResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResponse;
import org.jboss.pnc.environmentdriver.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
     * Create new build environment for a given configuration. EnvironmentId which is created based on
     * {@link EnvironmentCreateRequest#getEnvironmentLabel()} is returned.
     */
    @Authenticated
    @POST
    @Path("/create")
    public CompletionStage<EnvironmentCreateResponse> create(EnvironmentCreateRequest environmentCreateRequest) {
        logger.info("Requested new environment: {}", environmentCreateRequest.getEnvironmentLabel());
        return driver.create(environmentCreateRequest);
    }

    /**
     * Based on the {@link EnvironmentCompleteRequest#isEnableDebug()} value destroys the environment or enables the ssh
     * connection to the environment.
     *
     */
    @Authenticated
    @PUT
    @Path("/complete")
    public CompletionStage<EnvironmentCompleteResponse> complete(
            EnvironmentCompleteRequest environmentCompleteRequest) {
        if (environmentCompleteRequest.isEnableDebug()) {
            logger.info("Requested environment debug: {}", environmentCompleteRequest.getEnvironmentId());
            return driver.enableDebug(environmentCompleteRequest.getEnvironmentId());
        } else {
            logger.info("Requested environment destroy: {}", environmentCompleteRequest.getEnvironmentLabel());
            return driver.destroyAll(environmentCompleteRequest.getEnvironmentLabel())
                    .thenApply(nul -> new EnvironmentCompleteResponse(null, -1));
        }
    }

    /**
     * The complete request have to hit the same service instance as create to cancel potentially active create
     * operations.
     */
    @Authenticated
    @PUT
    @Path("/cancel/{environmentId}")
    public CompletionStage<EnvironmentCompleteResponse> cancel(@PathParam("environmentId") String environmentId) {
        logger.info("Requested environment destroy: {}", environmentId);
        return driver.destroy(environmentId).thenApply(nul -> new EnvironmentCompleteResponse(null, -1));
    }
}
