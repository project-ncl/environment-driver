package org.jboss.pnc.environmentdriver.clients;

import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.pnc.environmentdriver.model.RTCreateTokenRequest;
import org.jboss.pnc.environmentdriver.model.RTToken;

@RegisterRestClient(configKey = "artifactory-client")
public interface ArtifactoryClient {

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/access/api/v1/tokens")
    RTToken createScopedToken(RTCreateTokenRequest scope, @HeaderParam("Authorization") String accessToken);

}
