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
package org.jboss.pnc.environmentdriver;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.api.enums.ResultStatus;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResult;
import org.jboss.pnc.bifrost.upload.BifrostLogUploader;
import org.jboss.pnc.environmentdriver.clients.ArtifactoryClient;
import org.jboss.pnc.environmentdriver.invokerserver.CallbackHandler;
import org.jboss.pnc.environmentdriver.model.RTCreateTokenRequest;
import org.jboss.pnc.environmentdriver.model.RTToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.security.TestSecurity;

/**
 * Tests environment creation with Artifactory token generation enabled.
 * Verifies that the assembled token scope correctly includes static fixed scopes and
 * the dynamic deploy scope derived from the build content ID.
 */
@QuarkusTest
@TestProfile(DriverWithArtifactoryTest.ArtifactoryEnabledProfile.class)
@TestSecurity(authorizationEnabled = false)
public class DriverWithArtifactoryTest extends AbstractDriverTest {

    public static class ArtifactoryEnabledProfile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> overrides = new HashMap<>();
            overrides.put("environment-driver.artifactory.enabled", "true");
            overrides.put("environment-driver.disable-indy-token-fetch", "true");
            return overrides;
        }
    }

    @InjectMock
    @RestClient
    ArtifactoryClient artifactoryClient;

    @InjectMock
    BifrostLogUploader bifrostLogUploader;

    @Test
    @Timeout(15)
    public void shouldCreateTokenWithDynamicDeployScope() throws URISyntaxException, InterruptedException {
        // given
        String buildContentId = "build-12345";
        RTToken stubbedToken = RTToken.builder().accessToken("mocked-access-token").build();
        ArgumentCaptor<RTCreateTokenRequest> tokenRequestCaptor = ArgumentCaptor
                .forClass(RTCreateTokenRequest.class);
        when(artifactoryClient.createScopedToken(tokenRequestCaptor.capture(), anyString())).thenReturn(stubbedToken);

        Request callbackRequest = new Request(
                Request.Method.POST,
                new URI("http://localhost:" + CALLBACK_PORT + "/" + CallbackHandler.class.getSimpleName()),
                Collections.singletonList(
                        new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        EnvironmentCreateRequest request = EnvironmentCreateRequest.builder()
                .environmentLabel("env1")
                .repositoryDeployUrl("https://artifactory.com/artifactory/NCL-mvn-" + buildContentId)
                .repositoryBuildContentId(buildContentId)
                .completionCallback(callbackRequest)
                .build();

        // when
        EnvironmentCreateResponse environmentCreateResponse = given().contentType(MediaType.APPLICATION_JSON)
                .headers(requestHeaders())
                .body(request)
                .when()
                .post("/create")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .as(EnvironmentCreateResponse.class);

        // then — wait for completion callback
        Request callback = callbackRequests.take();
        EnvironmentCreateResult creationCompleted = mapper
                .convertValue(callback.getAttachment(), EnvironmentCreateResult.class);
        logger.info("Environment creation completed with status: {}", creationCompleted.getStatus());
        Assertions.assertEquals(ResultStatus.SUCCESS, creationCompleted.getStatus());

        // verify the token scope
        RTCreateTokenRequest capturedRequest = tokenRequestCaptor.getValue();
        String scope = capturedRequest.scope();
        logger.info("Captured Artifactory token scope: {}", scope);

        assertThat(scope).contains("artifact:NCL-*:r");
        assertThat(scope).contains("artifact:NCL-???-" + buildContentId + ":r,w,d");

        // clean up
        given().contentType(MediaType.APPLICATION_JSON)
                .headers(requestHeaders())
                .body(request)
                .when()
                .put("/cancel/" + environmentCreateResponse.getEnvironmentId())
                .then()
                .statusCode(200);
    }

    @Test
    @Timeout(15)
    public void shouldCreateTokenWithDynamicDeployScopeForTempBuild()
            throws URISyntaxException, InterruptedException {
        // given
        String buildContentId = "build-67890";
        String tempDeployUrl = "https://artifactory.com/artifactory/NCL-mvn-temp-" + buildContentId;
        RTToken stubbedToken = RTToken.builder().accessToken("mocked-access-token").build();
        ArgumentCaptor<RTCreateTokenRequest> tokenRequestCaptor = ArgumentCaptor
                .forClass(RTCreateTokenRequest.class);
        when(artifactoryClient.createScopedToken(tokenRequestCaptor.capture(), anyString())).thenReturn(stubbedToken);

        Request callbackRequest = new Request(
                Request.Method.POST,
                new URI("http://localhost:" + CALLBACK_PORT + "/" + CallbackHandler.class.getSimpleName()),
                Collections.singletonList(
                        new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        EnvironmentCreateRequest request = EnvironmentCreateRequest.builder()
                .environmentLabel("env2")
                .repositoryDeployUrl(tempDeployUrl)
                .repositoryBuildContentId(buildContentId)
                .completionCallback(callbackRequest)
                .build();

        // when
        EnvironmentCreateResponse environmentCreateResponse = given().contentType(MediaType.APPLICATION_JSON)
                .headers(requestHeaders())
                .body(request)
                .when()
                .post("/create")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .as(EnvironmentCreateResponse.class);

        // then — wait for completion callback
        Request callback = callbackRequests.take();
        EnvironmentCreateResult creationCompleted = mapper
                .convertValue(callback.getAttachment(), EnvironmentCreateResult.class);
        logger.info("Environment creation completed with status: {}", creationCompleted.getStatus());
        Assertions.assertEquals(ResultStatus.SUCCESS, creationCompleted.getStatus());

        // verify the token scope includes the temp- prefix for temporary build repos
        RTCreateTokenRequest capturedRequest = tokenRequestCaptor.getValue();
        String scope = capturedRequest.scope();
        logger.info("Captured Artifactory token scope for temp build: {}", scope);

        assertThat(scope).contains("artifact:NCL-*:r");
        assertThat(scope).contains("artifact:NCL-???-temp-" + buildContentId + ":r,w,d");
        assertThat(scope).doesNotContain("artifact:NCL-???-" + buildContentId + ":r,w,d");

        // clean up
        given().contentType(MediaType.APPLICATION_JSON)
                .headers(requestHeaders())
                .body(request)
                .when()
                .put("/cancel/" + environmentCreateResponse.getEnvironmentId())
                .then()
                .statusCode(200);
    }

}
