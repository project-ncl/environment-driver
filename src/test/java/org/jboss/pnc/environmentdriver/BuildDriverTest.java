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

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import io.undertow.util.Headers;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.api.TaskStatusUpdateEvent;
import org.jboss.pnc.environmentdriver.buildagent.Server;
import org.jboss.pnc.environmentdriver.dto.BuildCompleted;
import org.jboss.pnc.environmentdriver.dto.BuildRequest;
import org.jboss.pnc.environmentdriver.dto.BuildResponse;
import org.jboss.pnc.environmentdriver.dto.CallbackContext;
import org.jboss.pnc.environmentdriver.dto.CancelRequest;
import org.jboss.pnc.environmentdriver.invokerserver.CallbackHandler;
import org.jboss.pnc.environmentdriver.invokerserver.CallbackServletFactory;
import org.jboss.pnc.environmentdriver.invokerserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MediaType;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.function.Consumer;

import static io.restassured.RestAssured.given;
import static org.jboss.pnc.environmentdriver.dto.Status.COMPLETED;
import static org.jboss.pnc.environmentdriver.dto.Status.INTERRUPTED;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@QuarkusTest
@TestSecurity(authorizationEnabled = false)
public class BuildDriverTest {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String BIND_HOST = "127.0.0.1";

    private static Path workingDirectory;
    private static HttpServer callbackServer;

    private static URI baseBuildAgentUri;

    private static final BlockingQueue<BuildCompleted> completedBuilds = new ArrayBlockingQueue<>(10);

    @BeforeAll
    public static void beforeClass() throws Exception {
        // uncomment to log all requests
        // RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

        workingDirectory = Files.createTempDirectory("termd-build-agent");
        workingDirectory.toFile().deleteOnExit();
        Server.startServer(BIND_HOST, 0, "", Optional.of(workingDirectory));
        baseBuildAgentUri = new URI("http://" + BIND_HOST + ":" + Server.getPort() + "/");

        callbackServer = new HttpServer();

        Consumer<BuildCompleted> completedBuildConsumer = (b) -> completedBuilds.add(b);
        CallbackServletFactory callbackServletFactory = new CallbackServletFactory(completedBuildConsumer);
        callbackServer.addServlet(CallbackHandler.class, Optional.of(callbackServletFactory));
        callbackServer.start(8082, BIND_HOST);
    }

    @AfterAll
    public static void afterClass() {
        Server.stopServer();
        callbackServer.stop();
    }

    @Test
    @Timeout(10)
    public void shouldStartAndCompleteSuccessfully() throws InterruptedException, URISyntaxException {

        Request callback = new Request(
                Request.Method.POST,
                new URI("http://localhost:8082/" + CallbackHandler.class.getSimpleName()),
                Collections.singleton(new Request.Header(Headers.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        BuildRequest buildRequest = new BuildRequest(
                "the-build",
                "not-used",
                "not-used",
                "exit 0",
                workingDirectory.toString(),
                baseBuildAgentUri.toString(),
                callback,
                false,
                null);

        // start the build
        BuildResponse buildResponse = given().contentType(MediaType.APPLICATION_JSON)
                .body(buildRequest)
                .when()
                .post("/build")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .as(BuildResponse.class);

        Request receivedCancel = buildResponse.getCancel();
        Assertions.assertNotNull(receivedCancel.getUri());

        logger.info("Waiting for result ...");
        BuildCompleted buildCompleted = completedBuilds.take();
        logger.info("Received {}.", buildCompleted);
        Assertions.assertEquals(COMPLETED, buildCompleted.getStatus());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    @Timeout(10)
    public void shouldStartAndCancelTheExecutionImmediately(boolean debugEnabled)
            throws InterruptedException, URISyntaxException {

        Request callback = new Request(
                Request.Method.POST,
                new URI("http://localhost:8082/" + CallbackHandler.class.getSimpleName()),
                Collections.singleton(new Request.Header(Headers.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        BuildRequest buildRequest = new BuildRequest(
                "the-build",
                "not-used",
                "not-used",
                "for i in {1..3}; do echo \"Sleeping $i times\"; sleep 1; done",
                workingDirectory.toString(),
                baseBuildAgentUri.toString(),
                callback,
                debugEnabled,
                null);

        // start the build
        BuildResponse buildResponse = given().contentType(MediaType.APPLICATION_JSON)
                .body(buildRequest)
                .when()
                .post("/build")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .as(BuildResponse.class);

        Request receivedCancel = buildResponse.getCancel();
        Assertions.assertNotNull(receivedCancel.getUri());

        CancelRequest cancelRequest = new CancelRequest(
                buildResponse.getBuildExecutionId(),
                baseBuildAgentUri.toString());

        // cancel the build
        RequestSpecification requestSpecification = given().contentType(MediaType.APPLICATION_JSON);
        buildResponse.getCancel()
                .getHeaders()
                .stream()
                .forEach(header -> requestSpecification.header(header.getName(), header.getValue())); // not part of the
                                                                                                      // test, inspect
                                                                                                      // the log for MDC
                                                                                                      // (look at
                                                                                                      // /cancel)
        requestSpecification.body(cancelRequest).when().put(receivedCancel.getUri()).then().statusCode(200);

        logger.info("Waiting for result ...");
        BuildCompleted buildCompleted = completedBuilds.take();
        logger.info("Received {}.", buildCompleted);
        Assertions.assertEquals(INTERRUPTED, buildCompleted.getStatus());
        Assertions.assertEquals(debugEnabled, buildCompleted.isDebugEnabled());
    }

    @Test
    @Timeout(5)
    public void shouldRejectCompletionRequestWhenFailsToNotifyInvoker() throws URISyntaxException {

        Request invokerCallback = new Request(
                Request.Method.POST,
                new URI("http://localhost:8082/not-found/" + CallbackHandler.class.getSimpleName()),
                Collections.singleton(new Request.Header(Headers.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON)));

        CallbackContext context = CallbackContext.builder()
                .invokerCallback(invokerCallback)
                .environmentBaseUrl(baseBuildAgentUri.toString())
                .build();

        TaskStatusUpdateEvent event = TaskStatusUpdateEvent.newBuilder()
                .newStatus(org.jboss.pnc.buildagent.api.Status.COMPLETED)
                .context(context)
                .build();

        given().contentType(MediaType.APPLICATION_JSON)
                .body(event)
                .when()
                .put("/internal/completed")
                .then()
                .statusCode(500);
    }

}
