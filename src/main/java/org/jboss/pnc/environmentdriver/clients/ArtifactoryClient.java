package org.jboss.pnc.environmentdriver.clients;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.pnc.environmentdriver.model.RTCreateTokenRequest;
import org.jboss.pnc.environmentdriver.model.RTRevokeTokenRequest;
import org.jboss.pnc.environmentdriver.model.RTToken;

@RegisterRestClient(configKey = "artifactory-client")
public interface ArtifactoryClient {

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/access/api/v1/tokens")
    RTToken createScopedToken(RTCreateTokenRequest scope, @HeaderParam("Authorization") String accessToken);

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/access/api/v1/tokens/revoke")
    void revokeToken(RTRevokeTokenRequest revoke, @HeaderParam("Authorization") String accessToken);
}
