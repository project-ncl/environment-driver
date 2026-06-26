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

package org.jboss.pnc.environmentdriver.invokerserver;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jboss.pnc.api.dto.Request;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class CallbackHandler extends HttpServlet {

    private final ObjectMapper mapper = new ObjectMapper();

    private final Consumer<Request> consumer;

    public CallbackHandler(Consumer<Request> consumer) {
        this.consumer = consumer;
    }

    @Override
    protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        Object object = mapper.readValue(servletRequest.getInputStream(), Object.class);
        Request request = new Request(
                Request.Method.valueOf(servletRequest.getMethod()),
                URI.create(servletRequest.getRequestURI()),
                Collections.emptyList(),
                object);
        consumer.accept(request);
    }

}
