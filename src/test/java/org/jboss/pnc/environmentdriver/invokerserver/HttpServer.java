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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.InstanceFactory;
import org.jboss.pnc.buildagent.server.BootstrapUndertow;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import static io.undertow.servlet.Servlets.servlet;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpServer {
    private Undertow undertow;

    private Map<Class<? extends Servlet>, InstanceFactory<? extends Servlet>> servlets = new HashMap<>();

    public void start(int port, String host) throws ServletException, NoSuchAlgorithmException {
        DeploymentInfo servletBuilder = deployment().setClassLoader(BootstrapUndertow.class.getClassLoader())
                .setContextPath("/")
                .setDeploymentName("ROOT.war");

        for (Class<? extends Servlet> servletClass : servlets.keySet()) {
            InstanceFactory<? extends Servlet> instanceFactory = servlets.get(servletClass);
            if (instanceFactory != null) {
                servletBuilder.addServlet(
                        servlet(servletClass.getSimpleName(), servletClass, instanceFactory)
                                .addMapping(servletClass.getSimpleName()));
            } else {
                servletBuilder.addServlet(
                        servlet(servletClass.getSimpleName(), servletClass).addMapping(servletClass.getSimpleName()));
            }
        }

        DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
        manager.deploy();

        HttpHandler servletHandler = manager.start();

        undertow = Undertow.builder().addHttpListener(port, host).setHandler(servletHandler).build();

        undertow.start();
    }

    public void stop() {
        undertow.stop();
    }

    public void addServlet(Class<? extends Servlet> servletClass, InstanceFactory<? extends Servlet> servletFactory) {
        this.servlets.put(servletClass, servletFactory);
    }
}
