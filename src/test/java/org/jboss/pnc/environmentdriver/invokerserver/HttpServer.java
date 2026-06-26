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

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import static io.undertow.servlet.Servlets.servlet;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.ServletException;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class HttpServer {
    private Undertow undertow;

    private Set<ServletDeployment> servlets = new HashSet<>();

    public void start(int port, String host) throws ServletException, NoSuchAlgorithmException {
        DeploymentInfo servletBuilder = deployment().setClassLoader(HttpServer.class.getClassLoader())
                .setContextPath("/")
                .setDeploymentName("ROOT.war");

        for (ServletDeployment deployment : servlets) {
            if (deployment.getInstanceFactory() != null) {
                servletBuilder.addServlet(
                        servlet(
                                deployment.getaClass().getSimpleName(),
                                deployment.getaClass(),
                                deployment.getInstanceFactory()).addMapping(deployment.getMapping()));
            } else {
                servletBuilder.addServlet(
                        servlet(deployment.getaClass().getSimpleName(), deployment.getaClass())
                                .addMapping(deployment.getMapping()));
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

    public void addServlet(ServletDeployment servletDeployment) {
        this.servlets.add(servletDeployment);
    }
}
