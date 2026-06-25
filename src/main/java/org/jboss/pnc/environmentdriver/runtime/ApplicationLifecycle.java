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

package org.jboss.pnc.environmentdriver.runtime;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.pnc.common.concurrent.Sequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@ApplicationScoped
public class ApplicationLifecycle {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationLifecycle.class);

    @ConfigProperty(name = "sequenceGenerator.nodeId", defaultValue = "-1") // nodeId + nodeIdOffset must be < 1024
    int nodeId;

    @ConfigProperty(name = "sequenceGenerator.nodeIdOffset", defaultValue = "0") // nodeId + nodeIdOffset must be < 1024
    int nodeIdOffset;

    private AtomicInteger activeOperations = new AtomicInteger();
    private boolean shuttingDown;

    void onStart(@Observes StartupEvent event) {
        logger.info("Application is starting...");
        if (nodeId > -1) {
            Sequence.setNodeId(nodeIdOffset + nodeId);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        logger.info("Application is shutting down...");
        shuttingDown = true;
        Duration shutdownTimeout = ConfigProvider.getConfig().getValue("quarkus.shutdown.timeout", Duration.class);
        Instant shutdownStarted = Instant.now();
        while (activeOperations.get() > 0) {
            if (Duration.between(shutdownStarted, Instant.now()).compareTo(shutdownTimeout) > 0) {
                logger.warn("Reached quarkus.shutdown.timeout: {}", shutdownTimeout.toString());
                break;
            }
            try {
                logger.info("Waiting for {} operations to complete ...", activeOperations.get());
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                logger.warn("Interrupted while waiting for operations to complete.", e);
                break;
            }
        }
    }

    public void addActiveOperation() {
        activeOperations.incrementAndGet();
    }

    public void removeActiveOperation() {
        activeOperations.decrementAndGet();
    }

    public boolean isShuttingDown() {
        return shuttingDown;
    }
}
