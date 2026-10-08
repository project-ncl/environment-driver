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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.jboss.pnc.api.constants.MDCHeaderKeys;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.environmentdriver.invokerserver.CallbackHandler;
import org.jboss.pnc.environmentdriver.invokerserver.HttpServer;
import org.jboss.pnc.environmentdriver.invokerserver.PingHandler;
import org.jboss.pnc.environmentdriver.invokerserver.ServletDeployment;
import org.jboss.pnc.environmentdriver.invokerserver.ServletInstanceFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;

/**
 * Base class for Driver integration tests. Manages the shared callback/ping HTTP server
 * infrastructure and provides common utilities used by all test subclasses.
 */
public abstract class AbstractDriverTest {

    protected static final String BIND_HOST = "127.0.0.1";
    protected static final int CALLBACK_PORT = 8082;

    protected static final Logger logger = LoggerFactory.getLogger(AbstractDriverTest.class);

    protected static final ObjectMapper mapper = new ObjectMapper();

    private static HttpServer callbackServer;

    protected static final BlockingQueue<Request> callbackRequests = new ArrayBlockingQueue<>(100);
    protected static final BlockingQueue<Request> pingRequests = new ArrayBlockingQueue<>(100);

    @BeforeAll
    public static void startCallbackServer() throws Exception {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

        callbackServer = new HttpServer();
        callbackServer.addServlet(
                new ServletDeployment(
                        CallbackHandler.class,
                        new ServletInstanceFactory(new CallbackHandler(callbackRequests::add))));
        callbackServer.addServlet(
                new ServletDeployment(
                        PingHandler.class,
                        new ServletInstanceFactory(new PingHandler(pingRequests::add)),
                        "/*"));
        callbackServer.start(CALLBACK_PORT, BIND_HOST);
    }

    @AfterAll
    public static void stopCallbackServer() {
        callbackServer.stop();
    }

    protected Map<String, String> requestHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(MDCHeaderKeys.PROCESS_CONTEXT.getHeaderName(), "A");
        headers.put(MDCHeaderKeys.TMP.getHeaderName(), "false");
        headers.put(MDCHeaderKeys.EXP.getHeaderName(), "0");
        headers.put(MDCHeaderKeys.USER_ID.getHeaderName(), "1");
        return headers;
    }
}
