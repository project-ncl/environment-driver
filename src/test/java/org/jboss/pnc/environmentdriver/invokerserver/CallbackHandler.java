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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.pnc.environmentdriver.dto.BuildCompleted;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class CallbackHandler extends HttpServlet {

    private final ObjectMapper mapper = new ObjectMapper();

    private final Consumer<BuildCompleted> consumer;

    public CallbackHandler(Consumer<BuildCompleted> consumer) {
        this.consumer = consumer;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        BuildCompleted buildCompleted = mapper.readValue(request.getInputStream(), BuildCompleted.class);
        consumer.accept(buildCompleted);
    }
}
