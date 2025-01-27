/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2014-2020 Red Hat, Inc., and individual contributors
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

import java.util.Optional;

import javax.enterprise.context.Dependent;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Dependent
public class Configuration {

    /**
     * List of allowed destinations by firewall in Docker container. <br />
     * Format: \<IPv4>:\<Port>(,\<IPv4>:\<Port>)+ You can set it to "all" and network isolation will be skipped, in case
     * of not setting it up at all all network traffic will be dropped
     */
    @ConfigProperty(name = "environment-driver.firewall-allowed-destinations", defaultValue = "127.0.0.1")
    String firewallAllowedDestinations;

    /**
     * Destinations that are allowed to go through the firewall
     */
    @ConfigProperty(name = "environment-driver.allowed-http-outgoing-destinations")
    Optional<String> allowedHttpOutgoingDestinations;

    /**
     * Persistent http proxy hostname
     */
    @ConfigProperty(name = "environment-driver.proxy-server")
    Optional<String> proxyServer;

    /**
     * Persistent http proxy port
     */
    @ConfigProperty(name = "environment-driver.proxy-port")
    Optional<String> proxyPort;

    /**
     * List of hosts that are not proxied.
     */
    @ConfigProperty(name = "environment-driver.non-proxy-hosts", defaultValue = "localhost")
    Optional<String> nonProxyHosts;

    /**
     * Working directory on the remote environment
     */
    @ConfigProperty(name = "environment-driver.working-directory")
    String workingDirectory;

    @ConfigProperty(name = "environment-driver.build-agent.service-scheme", defaultValue = "http")
    String buildAgentServiceScheme;

    @ConfigProperty(name = "environment-driver.build-agent.container-port", defaultValue = "8080")
    String buildAgentContainerPort;

    @ConfigProperty(name = "environment-driver.build-agent.host", defaultValue = "localhost")
    String buildAgentHost;

    @ConfigProperty(name = "environment-driver.build-agent.ping-path", defaultValue = "/")
    String buildAgentPingPath;

    @ConfigProperty(name = "environment-driver.build-agent.running-wait-for", defaultValue = "30")
    long buildAgentRunningWaitFor;

    @ConfigProperty(name = "environment-driver.builder-pod-memory", defaultValue = "4")
    int builderPodMemory;

    @ConfigProperty(name = "environment-driver.self-base-url")
    String thisServiceBaseUrl;

    @ConfigProperty(name = "environment-driver.openshift.ssh-service-port-name", defaultValue = "2222-ssh")
    String sshServicePortName;

    @ConfigProperty(name = "environment-driver.openshift.pod")
    String podDefinition;

    @ConfigProperty(name = "environment-driver.openshift.service")
    String serviceDefinition;

    @ConfigProperty(name = "environment-driver.openshift.ssh-service")
    String sshServiceDefinition;

    @ConfigProperty(name = "environment-driver.openshift.route")
    String routeDefinition;

    @ConfigProperty(name = "environment-driver.http-client.connect-timeout", defaultValue = "5")
    int httpClientConnectTimeout;

    @ConfigProperty(name = "environment-driver.http-client.request-timeout", defaultValue = "15")
    int httpClientRequestTimeout;

    @ConfigProperty(name = "environment-driver.ssh-ping-retry-duration", defaultValue = "15")
    int sshPingRetryDuration;

    @ConfigProperty(name = "environment-driver.destroy-retry-duration", defaultValue = "3600")
    long destroyRetryDuration;

    @ConfigProperty(name = "environment-driver.pod-running-wait-for", defaultValue = "300")
    long podRunningWaitFor;

    @ConfigProperty(name = "environment-driver.service-running-wait-for", defaultValue = "30")
    long serviceRunningWaitFor;

    @ConfigProperty(name = "environment-driver.callback-retry-duration", defaultValue = "300")
    long callbackRetryDuration;

    @ConfigProperty(name = "environment-driver.build-agent.running-retry-delay-msec", defaultValue = "500")
    long buildAgentRunningRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.build-agent.running-retry-max-delay-msec", defaultValue = "2000")
    long buildAgentRunningRetryMaxDelayMsec;

    @ConfigProperty(name = "environment-driver.ssh-ping-retry-delay-msec", defaultValue = "500")
    long sshPingRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.ssh-ping-retry-max-delay-msec", defaultValue = "2000")
    long sshPingRetryMaxDelayMsec;

    @ConfigProperty(name = "environment-driver.destroy-retry-delay-msec", defaultValue = "1000")
    long destroyRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.destroy-retry-max-delay-msec", defaultValue = "10000")
    long destroyRetryMaxDelayMsec;

    @ConfigProperty(name = "environment-driver.pod-running-retry-delay-msec", defaultValue = "1000")
    long podRunningRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.pod-running-retry-max-delay-msec", defaultValue = "5000")
    long podRunningRetryMaxDelayMsec;

    @ConfigProperty(name = "environment-driver.service-running-retry-delay-msec", defaultValue = "500")
    long serviceRunningRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.service-running-retry-max-delay-msec", defaultValue = "5000")
    long serviceRunningRetryMaxDelayMsec;

    @ConfigProperty(name = "environment-driver.callback-retry-delay-msec", defaultValue = "500")
    long callbackRetryDelayMsec;

    @ConfigProperty(name = "environment-driver.callback-retry-max-delay-msec", defaultValue = "5000")
    long callbackRetryMaxDelayMsec;
}
