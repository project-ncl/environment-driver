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

import io.quarkus.arc.config.ConfigProperties;
import lombok.Getter;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Getter
@ConfigProperties(prefix = "environment-driver")
public class Configuration {

    /**
     * List of allowed destinations by firewall in Docker container. <br />
     * Format: \<IPv4>:\<Port>(,\<IPv4>:\<Port>)+ You can set it to "all" and network isolation will be skipped, in case
     * of not setting it up at all all network traffic will be dropped
     */
    protected String firewallAllowedDestinations;

    /**
     * Persistent http proxy hostname
     */
    protected String proxyServer;

    /**
     * Persistent http proxy port
     */
    protected String proxyPort;

    /**
     * List of hosts that are not proxied.
     */
    protected String nonProxyHosts;

    /**
     * Working directory on the remote environment
     */
    protected String workingDirectory;

    protected String buildAgentHost;
    protected String buildAgentBindPath;

    protected String containerPort;

    @ConfigProperty(defaultValue = "4")
    protected int builderPodMemory;

    @ConfigProperty(defaultValue = "2222-ssh")
    protected String sshServicePortName;

    protected String thisServiceBaseUrl;

    @ConfigProperty(name = "openshift.namespace")
    protected String openshiftNamespace;

    @ConfigProperty(name = "openshift.pod")
    protected String podDefinition;

    @ConfigProperty(name = "openshift.service")
    protected String serviceDefinition;

    @ConfigProperty(name = "openshift.ssh-service")
    protected String sshServiceDefinition;

    @ConfigProperty(name = "openshift.route")
    protected String routeDefinition;

    @ConfigProperty(name = "openshift.api.url")
    protected String openshiftApiUrl;

    /**
     * Openshift Api authentication token.
     */
    @ConfigProperty(name = "openshift.api.token")
    protected String openshiftApiToken;

    @ConfigProperty(name = "openshift.client.connection-timeout", defaultValue = "5")
    private int openshiftClientConnectionTimeout;

    @ConfigProperty(name = "openshift.client.request-timeout", defaultValue = "15")
    private int openshiftClientRequestTimeout;

    @ConfigProperty(name = "http.connect-timeout", defaultValue = "5")
    private int httpClientConnectTimeout;

    @ConfigProperty(name = "http.request-timeout", defaultValue = "15")
    private int httpClientRequestTimeout;

    @ConfigProperty(name = "ssh-ping.retry-duration", defaultValue = "15")
    private int sshPingRetryMaxDuration;

    @ConfigProperty(name = "destroy.retry-duration", defaultValue = "3600")
    private long destroyRetryMaxDuration;

    @ConfigProperty(name = "pod-running.wait-for", defaultValue = "300")
    private long podRunningWaitFor;

    @ConfigProperty(name = "service-running.wait-for", defaultValue = "30")
    private long serviceRunningWaitFor;

    @ConfigProperty(name = "build-agent-running.wait-for", defaultValue = "15")
    private long buildAgentRunningWaitFor;

    @ConfigProperty(name = "callback.max-duration", defaultValue = "60")
    private long callbackRetryMaxDuration;

}
