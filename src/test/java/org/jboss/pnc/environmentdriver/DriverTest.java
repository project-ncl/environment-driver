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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;

import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.api.enums.ResultStatus;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResult;
import org.jboss.pnc.api.indy.dto.IndyTokenRequestDTO;
import org.jboss.pnc.api.indy.dto.IndyTokenResponseDTO;
import org.jboss.pnc.bifrost.upload.BifrostLogUploader;
import org.jboss.pnc.bifrost.upload.LogMetadata;
import org.jboss.pnc.environmentdriver.clients.IndyService;
import org.jboss.pnc.environmentdriver.invokerserver.CallbackHandler;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@QuarkusTest
@TestSecurity(authorizationEnabled = false)
public class DriverTest extends AbstractDriverTest {

    @InjectMock
    @RestClient
    IndyService indyService;

    @InjectMock
    BifrostLogUploader bifrostLogUploader;

    @BeforeEach
    public void setup() {
        when(indyService.getAuthToken(any(IndyTokenRequestDTO.class), any(String.class)))
                .thenReturn(new IndyTokenResponseDTO("token-for-builder-pod"));
    }

    @Test
    @Timeout(15)
    public void shouldCreateEnvironmentAndSendCompletionCallback() throws URISyntaxException, InterruptedException {
        Request callbackRequest = new Request(
                Request.Method.POST,
                new URI("http://localhost:8082/" + CallbackHandler.class.getSimpleName()),
                Collections.singletonList(
                        new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        // when create the environment
        EnvironmentCreateRequest request = EnvironmentCreateRequest.builder()
                .environmentLabel("env1")
                .completionCallback(callbackRequest)
                .build();
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

        String environmentId = environmentCreateResponse.getEnvironmentId();
        logger.info("Environment id: {}", environmentId);

        // then
        Assertions.assertTrue(environmentId.contains("env1"));
        Request callback = callbackRequests.take();
        EnvironmentCreateResult creationCompleted = mapper
                .convertValue(callback.getAttachment(), EnvironmentCreateResult.class);
        logger.info("Environment creation completed with status: {}", creationCompleted.getStatus());
        Assertions.assertEquals(
                ResultStatus.SUCCESS,
                creationCompleted.getStatus(),
                "Unexpected environment creation status.");
        Assertions.assertEquals(2, pingRequests.size(), "Unexpected number of received pings.");

        // verify bifrost log uploader was called
        verify(bifrostLogUploader, times(1)).uploadString(any(String.class), any(LogMetadata.class));

        // clean up
        EnvironmentCreateRequest destroyRequest = EnvironmentCreateRequest.builder()
                .environmentLabel("env1")
                .completionCallback(callbackRequest)
                .build();
        given().contentType(MediaType.APPLICATION_JSON)
                .headers(requestHeaders())
                .body(destroyRequest)
                .when()
                .put("/cancel/" + environmentId)
                .then()
                .statusCode(200)
                .extract()
                .body()
                .as(EnvironmentCreateResponse.class);
    }

    @Test
    @Timeout(10)
    public void shouldFailCreateRequest() throws URISyntaxException, InterruptedException {
        String originalPod = ConfigProvider.getConfig().getValue("environment-driver.openshift.pod", String.class);
        System.setProperty("environment-driver.openshift.pod", "unparsable");
        try {
            Request callbackRequest = new Request(
                    Request.Method.POST,
                    new URI("http://localhost:8082/" + CallbackHandler.class.getSimpleName()),
                    Collections.singletonList(
                            new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

            // when create the environment
            EnvironmentCreateRequest request = EnvironmentCreateRequest.builder()
                    .environmentLabel("env1")
                    .completionCallback(callbackRequest)
                    .build();
            given().contentType(MediaType.APPLICATION_JSON)
                    .headers(requestHeaders())
                    .body(request)
                    .when()
                    .post("/create")
                    .then()
                    .statusCode(400);
        } finally {
            System.setProperty("environment-driver.openshift.pod", originalPod);
        }
    }

    @Test
    @Timeout(15)
    public void shouldCallbackWithFailedResultWhenBuildAgentPingFails()
            throws URISyntaxException, InterruptedException {
        String originalService = ConfigProvider.getConfig()
                .getValue("environment-driver.openshift.service", String.class);
        System.setProperty("environment-driver.openshift.service", originalService.replace("127.0.0.1", "127.1.2.3"));
        try {
            Request callbackRequest = new Request(
                    Request.Method.POST,
                    new URI("http://localhost:8082/" + CallbackHandler.class.getSimpleName()),
                    Collections.singletonList(
                            new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

            // when create the environment
            EnvironmentCreateRequest request = EnvironmentCreateRequest.builder()
                    .environmentLabel("env1")
                    .completionCallback(callbackRequest)
                    .build();
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

            String environmentId = environmentCreateResponse.getEnvironmentId();
            logger.info("Environment id: {}", environmentId);

            // then
            Request callback = callbackRequests.take();
            EnvironmentCreateResult creationCompleted = mapper
                    .convertValue(callback.getAttachment(), EnvironmentCreateResult.class);
            logger.info("Environment creation completed with status: {}", creationCompleted.getStatus());
            String message = "Unexpected environment creation status.";
            Assertions.assertEquals(ResultStatus.FAILED, creationCompleted.getStatus(), message);
            logger.info("CreationCompleted.message: [{}]", creationCompleted.getStatus());
            Assertions.assertEquals(0, pingRequests.size(), "Unexpected number of received pings.");

            // verify bifrost log uploader was called
            verify(bifrostLogUploader, times(1)).uploadString(any(String.class), any(LogMetadata.class));

            // clean up
            EnvironmentCreateRequest destroyRequest = EnvironmentCreateRequest.builder()
                    .environmentLabel("env1")
                    .completionCallback(callbackRequest)
                    .build();
            given().contentType(MediaType.APPLICATION_JSON)
                    .headers(requestHeaders())
                    .body(destroyRequest)
                    .when()
                    .put("/cancel/" + environmentId)
                    .then()
                    .statusCode(200)
                    .extract()
                    .body()
                    .as(EnvironmentCreateResponse.class);
        } finally {
            System.setProperty("environment-driver.openshift.service", originalService);
        }
    }

}
