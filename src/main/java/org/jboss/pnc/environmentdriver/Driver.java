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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodList;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceList;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.openshift.api.model.Route;
import io.fabric8.openshift.client.DefaultOpenShiftClient;
import io.fabric8.openshift.client.OpenShiftClient;
import io.undertow.util.Headers;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.pnc.api.constants.MDCKeys;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.RandomUtils;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.common.Strings;
import org.jboss.pnc.common.constants.MDCHeaderKeys;
import org.jboss.pnc.environmentdriver.dto.CompleteResponse;
import org.jboss.pnc.environmentdriver.dto.CreateRequest;
import org.jboss.pnc.environmentdriver.dto.CreateResponse;
import org.jboss.pnc.environmentdriver.dto.EnvironmentCreationCompleted;
import org.jboss.pnc.pncmetrics.GaugeMetric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_FAILED_REASON_KEY;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@RequestScoped
public class Driver {

    private static final Logger logger = LoggerFactory.getLogger(Driver.class);

    /**
     * From: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
     *
     * ErrImagePull and ImagePullBackOff added to that list. The pod.getStatus() call will return the *reason* of
     * failure, and if the reason is not available, then it'll return the regular status (as mentioned in the link)
     *
     * For pod creation, the failure reason we expect when docker registry is not behaving is 'ErrImagePull' or
     * 'ImagePullBackOff'
     *
     * 'Error' and 'InvalidImageName' statuses were added as per NCL-6032 investigations
     */
    private static final String[] POD_FAILED_STATUSES = { "Failed", "Unknown", "CrashLoopBackOff", "ErrImagePull",
            "ImagePullBackOff", "Error", "InvalidImageName" };

    @Inject
    ManagedExecutor executor;

    @Inject
    JsonWebToken webToken;

    @Inject
    Configuration configuration;

    @Inject
    ObjectMapper mapper;

    @Inject
    ActiveMonitors activeMonitors;

    private OpenShiftClient client;
    private java.net.http.HttpClient httpClient;

    private Optional<GaugeMetric> gaugeMetric = Optional.empty(); //TODO

    @PostConstruct
    void init() {
        Config config = new ConfigBuilder()
                .withNamespace(configuration.getOpenshiftNamespace())
                .withMasterUrl(configuration.getOpenshiftApiUrl())
                .withOauthToken(configuration.getOpenshiftApiToken())
                .withConnectionTimeout(configuration.getOpenshiftClientConnectionTimeout())
                .withRequestTimeout(configuration.getOpenshiftClientRequestTimeout())
                .build();
        client = new DefaultOpenShiftClient(config);

        httpClient = java.net.http.HttpClient.newBuilder()
                .executor(executor)
                .connectTimeout(Duration.ofSeconds(configuration.getHttpClientConnectTimeout()))
                .build();
    }

    /**
     * Calls the Openshift API to create required resources. Method does not wait for the resources to become available,
     * when the resources are available the callback to the invoker is executed.
     * If the resource creation requests fail, the CompletionStage is completed exceptionally.
     * To keep the required state minimal, the retries should be handled externally.
     *
     * @return CompletionStage which is completed when all required requests to the Openshift complete.
     */
    public CompletionStage<CreateResponse> create(CreateRequest createRequest) {
        String environmentId = createRequest.getEnvironmentLabel() + "-" + RandomUtils.randString(6);

        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);

        Map<String, String> environmentVariables = new HashMap<>();

        boolean proxyActive = !StringUtils.isEmpty(configuration.getProxyServer())
                && !StringUtils.isEmpty(configuration.getProxyPort());

        environmentVariables.put("image", createRequest.getImageId());
        environmentVariables.put("firewallAllowedDestinations", configuration.getFirewallAllowedDestinations());
        environmentVariables.put("isHttpActive", Boolean.toString(proxyActive).toLowerCase());
        environmentVariables.put("proxyServer", configuration.getProxyServer());
        environmentVariables.put("proxyPort", configuration.getProxyPort());
        environmentVariables.put("nonProxyHosts", configuration.getNonProxyHosts());

        environmentVariables.put("AProxDependencyUrl", createRequest.getRepositoryDependencyUrl());
        environmentVariables.put("AProxDeployUrl", createRequest.getRepositoryDeployUrl());

        environmentVariables.put("containerPort", configuration.getContainerPort());
        environmentVariables.put("buildContentId", createRequest.getRepositoryBuildContentId());
        environmentVariables.put("accessToken", webToken.getRawToken());

        try {
            environmentVariables.putAll(mdcToMap());
        } catch (DriverException e) {
            return CompletableFuture.failedFuture(e);
        }

        environmentVariables.put("resourcesMemory", builderPodMemory(
                configuration.getBuilderPodMemory(),
                createRequest.getPodMemoryOverride()));

        String buildAgentContextPath = "pnc-ba-" + environmentId;

        environmentVariables.put("environment-label", createRequest.getEnvironmentLabel());
        environmentVariables.put("pod-name", podName);
        environmentVariables.put("service-name", serviceName);
        environmentVariables.put("buildAgentContextPath", "/" + buildAgentContextPath);

        String sshPassword;
        if (createRequest.isAllowSshDebug()) {
            sshPassword = RandomStringUtils.randomAlphanumeric(10);
            environmentVariables.put("workerUserPassword", sshPassword);
        } else {
            sshPassword = "";
        }

        CompletableFuture<Pod> podFuture = CompletableFuture.supplyAsync(() -> {
                Pod podCreationModel = createModelNode(
                        configuration.getPodDefinition(),
                        environmentVariables,
                        Pod.class);
                return client.pods().create(podCreationModel);
            }, executor);

        CompletableFuture<Service> serviceFuture = CompletableFuture.supplyAsync(() -> {
                Service serviceCreationModel = createModelNode(
                        configuration.getServiceDefinition(),
                        environmentVariables,
                        Service.class);
                return client.services().create(serviceCreationModel);
            }, executor
        );

        CompletableFuture<Void> podAndServiceFuture = CompletableFuture.allOf(podFuture, serviceFuture);

        return podAndServiceFuture
                .thenApplyAsync((nul) -> startMonitor(serviceName, podName, createRequest.getCompletionCallback(), sshPassword), executor)
                .thenApplyAsync((nul) -> new CreateResponse(environmentId, getCancelRequest(environmentId)), executor);
    }

    private Request getCancelRequest(String environmentId) {
        return Request.builder()
                .method(Request.Method.PUT)
                .uri(URI.create(configuration.getThisServiceBaseUrl() + "/cancel/" + environmentId))
                .headers(getHeaders())
                .build();
    }

    public CompletionStage<CompleteResponse> enableDebug(String environmentId) {
        Map<String, String> serviceEnvVariables = new HashMap<>();
        serviceEnvVariables.put("pod-name", getPodName(environmentId));
        serviceEnvVariables.put("ssh-service-name", getSshServiceName(environmentId));

        Map<String, String> routeEnvVariables = new HashMap<>();
        routeEnvVariables.put("route-name", "pnc-ba-route-" + environmentId);
        routeEnvVariables.put("route-path", "/pnc-ba-" + environmentId);
        routeEnvVariables.put("service-name", getServiceName(environmentId));
        routeEnvVariables.put("build-agent-host", configuration.getBuildAgentHost());

        // Enable ssh forwarding and complete with the port to which ssh is forwarded
        return CompletableFuture.supplyAsync(() -> {
            Service serviceCreationModel = createModelNode(
                    configuration.getSshServiceDefinition(),
                    serviceEnvVariables,
                    Service.class);
            Service sshService = client.services().create(serviceCreationModel);
            return sshService.getSpec()
                    .getPorts()
                    .stream()
                    .filter(m -> m.getName().equals(configuration.getSshServicePortName()))
                    .findAny()
                    .orElseThrow(() -> new RuntimeException("No ssh service in response! Service data: " + sshService))
                    .getNodePort();
            }, executor)
        .thenApplyAsync(sshPort -> {
            Route routeCreationModel = createModelNode(
                    configuration.getRouteDefinition(),
                    routeEnvVariables,
                    Route.class);
            Route route = (Route) client.routes().create(routeCreationModel); //TODO remove cast
            String sshHost = route.getSpec().getHost();
            return new InetSocketAddress(sshHost, sshPort);
        }, executor)
        .thenComposeAsync(this::pingSsh)
        .thenApplyAsync(socketAddr -> new CompleteResponse(socketAddr.getHostName(), socketAddr.getPort()));
    }

    private CompletableFuture<InetSocketAddress> pingSsh(InetSocketAddress inetSocketAddress) {
        RetryPolicy<InetSocketAddress> retryPolicy = new RetryPolicy<InetSocketAddress>()
                .withMaxDuration(Duration.ofSeconds(configuration.getSshPingRetryMaxDuration()))
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .onRetry(ctx -> logger.warn("Ssh ping retry attempt:{}, last error:{}",
                                            ctx.getAttemptCount(),
                                            ctx.getLastFailure()));
        return Failsafe.with(retryPolicy)
                .with(executor)
                .getAsync(() -> {
                    Socket socket = new Socket();
                    try {
                        socket.connect(inetSocketAddress, configuration.getHttpClientConnectTimeout() * 1000);
                        logger.info("Ssh-ping success.");
                    } finally {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            logger.warn("Failed to clean-up after ssh-ping.");
                        }
                    }
                    return inetSocketAddress;
                });
    }

    /**
     * Method will try its best to destroy the environment.
     * Fire and forget operation.
     */
    public CompletionStage<Void> destroy(String environmentId) {
        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);
        activeMonitors.cancel(podName);

        RetryPolicy<String> retryPolicy = new RetryPolicy<String>()
                .withMaxDuration(Duration.ofSeconds(configuration.getDestroyRetryMaxDuration()))
                .withBackoff(1000, 10000, ChronoUnit.MILLIS)
                .abortOn(UnableToStartException.class);

        //delete service
        Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    Service service = client.services().withName(serviceName).get();
                    if (service != null) {
                        if (client.services().delete(service)) {
                            logger.info("Service {} deleted.", serviceName);
                        } else {
                            logger.warn("Service {} was not deleted.", serviceName);
                        }
                    } else {
                        logger.warn("Service {} does not exists.", serviceName);
                    }
                });
        //delete pod
        Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    Pod pod = client.pods().withName(podName).get();
                    if (pod != null) {
                        if (client.pods().delete(pod)) {
                            logger.info("Pod {} deleted.", podName);
                        } else {
                            logger.warn("Pod {} was not deleted.", podName);
                        }
                    } else {
                        logger.warn("Pod {} does not exists.", podName);
                    }
                });
        return null;
    }

    /**
     * Method will try its best to destroy all the environments created from given environmentName.
     * Fire and forget operation.
     */
    public CompletionStage<Void> destroyAll(String environmentLabel) {
        RetryPolicy<String> retryPolicy = new RetryPolicy<String>()
                .withMaxDuration(Duration.ofSeconds(configuration.getDestroyRetryMaxDuration()))
                .withBackoff(1000, 10000, ChronoUnit.MILLIS)
                .abortOn(UnableToStartException.class);

        //delete service
        Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    ServiceList serviceList = client.services().withLabel("environment", environmentLabel).list();
                    if (serviceList != null) {
                        if (client.services().delete(serviceList.getItems())) {
                            logger.info("Services {} deleted.", serviceList.getItems());
                        } else {
                            logger.warn("Services {} were not deleted.", serviceList.getItems());
                        }
                    } else {
                        logger.warn("No services found by label {}.", environmentLabel);
                    }
                });
        //delete pod
        Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    PodList podList = client.pods().withLabel("environment", environmentLabel).list();
                    if (podList != null) {
                        if (client.pods().delete(podList.getItems())) {
                            logger.info("Pods {} deleted.", podList.getItems());
                        } else {
                            logger.warn("Pods {} were not deleted.", podList.getItems());
                        }
                    } else {
                        logger.warn("No pods found by label {}.", environmentLabel);
                    }
                });
        return null;
    }

    private Void startMonitor(String serviceName, String podName, Request completionCallback, String sshPassword) {
        CompletableFuture<String> serviceRunning = isServiceRunning(serviceName);
        activeMonitors.add(podName, serviceRunning);

        CompletableFuture<Void> podRunning = isPodRunning(podName);
        activeMonitors.add(podName, podRunning);

        CompletableFuture.allOf(podRunning, serviceRunning)
                .thenComposeAsync((nul) -> {
                    String serviceIp = serviceRunning.join(); //future already completed (allOff)
                    CompletableFuture<Void> pingFuture = pingBuildAgent(serviceName, serviceIp);
                    activeMonitors.add(podName, pingFuture);
                    return pingFuture.thenApply((n) -> serviceIp);
                })
                .handleAsync((serviceIp, throwable) -> {
                    activeMonitors.remove(podName);
                    if (throwable != null) {
                        if (throwable instanceof CancellationException) {
                            callback(completionCallback, EnvironmentCreationCompleted.cancelled());
                        } else {
                            callback(completionCallback, EnvironmentCreationCompleted.failed(throwable));
                        }
                    } else {
                        EnvironmentCreationCompleted environmentCreationCompleted = EnvironmentCreationCompleted.success(
                                getEnvironmentBaseUri(serviceIp),
                                configuration.getWorkingDirectory(),
                                sshPassword
                        );
                        callback(completionCallback, environmentCreationCompleted);
                    }
                    return null;
                });
        return null;
    }

    /**
     * Check if pod is in running state. If pod is in one of the failure statuses (as specified in POD_FAILED_STATUSES,
     * {@link CompletableFuture} is compelted with {@link UnableToStartException}
     *
     * @return boolean: is pod running?
     */
    private CompletableFuture<Void> isPodRunning(String podName) {
        RetryPolicy<String> retryPolicy = new RetryPolicy<String>()
                .withMaxDuration(Duration.ofSeconds(configuration.getPodRunningWaitFor()))
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .abortOn(UnableToStartException.class);
        return Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    Pod pod = client.pods().withName(podName).get();
                    String podStatus = pod.getStatus().getPhase();
                    logger.debug("Pod {} status: {}", pod.getMetadata().getName(), podStatus);
                    if (Arrays.asList(POD_FAILED_STATUSES).contains(podStatus)) {
                        gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_REASON_KEY + "." + podStatus));
                        throw new UnableToStartException("Pod failed with status: " + podStatus);
                    }
                    boolean isRunning = "Running".equals(pod.getStatus().getPhase());
                    if (isRunning) {
                        logger.debug("Pod {} running.", pod.getMetadata().getName());
                    } else {
                        throw new DriverException("Pod is not running.");
                    }
                });
    }

    private CompletableFuture<String> isServiceRunning(String serviceName) {
        RetryPolicy<Object> retryPolicy = new RetryPolicy<>()
                .withMaxDuration(Duration.ofSeconds(configuration.getServiceRunningWaitFor()))
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .onRetry(ctx -> logger.warn("Is service running retry attempt:{}, last error:{}",
                                            ctx.getAttemptCount(),
                                            ctx.getLastFailure()));
        return Failsafe.with(retryPolicy)
                .with(executor)
                .getAsync(() -> {
                    Service service = client.services().withName(serviceName).get();
                    String clusterIP = service.getSpec().getClusterIP();
                    if (clusterIP == null) {
                        throw new DriverException("Service " + serviceName + " is not running.");
                    } else {
                        logger.info("Service {} ip: {}.",serviceName, clusterIP);
                        return clusterIP;
                    }
                });
    }

    private CompletableFuture<Void> pingBuildAgent(String serviceName, String serviceIp) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(getEnvironmentBaseUri(serviceIp))
                .method(Request.Method.HEAD.name(), HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(configuration.getHttpClientRequestTimeout()));
        HttpRequest request = builder.build();
        RetryPolicy<HttpResponse<String>> retryPolicy = new RetryPolicy<HttpResponse<String>>()
                .handleIf((response,throwable) -> throwable != null || !isHttpSuccess(response.statusCode()))
                .withMaxDuration(Duration.ofSeconds(configuration.getBuildAgentRunningWaitFor()))
                .withBackoff(500, 2000, ChronoUnit.MILLIS)
                .onRetry(ctx -> logger.warn("BuildAgent ping retry attempt:{}, last status:{}, last error:{}",
                                            ctx.getAttemptCount(),
                                            ctx.getLastResult().statusCode(),
                                            ctx.getLastFailure()));
        return Failsafe.with(retryPolicy)
                .with(executor)
                .getStageAsync(() -> httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()))
                .handleAsync((resp, t) -> {
                    if (t != null) {
                        logger.error("Unable to ping build agent: " + serviceName, t);
                    } else {
                        logger.info("Ping to {} responded with status: {}.", serviceName, resp.statusCode());
                    }
                    return null;
                });
    }

    private URI getEnvironmentBaseUri(String serviceIp) {
        return URI.create("https://" + serviceIp + "/"
                + configuration.getBuildAgentBindPath());
    }

    private void callback(Request callback, EnvironmentCreationCompleted environmentCreationCompleted) {
        String body;
        try {
            body = mapper.writeValueAsString(environmentCreationCompleted);
        } catch (JsonProcessingException e) {
            logger.error("Cannot serialize callback object.", e);
            body = "";
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(callback.getUri())
                .method(callback.getMethod().name(), HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(configuration.getHttpClientRequestTimeout()));
        callback.getHeaders().forEach(h -> builder.header(h.getName(), h.getValue()));
        HttpRequest request = builder.build();

        RetryPolicy<HttpResponse<String>> retryPolicy = new RetryPolicy<HttpResponse<String>>()
                .handleIf((response,throwable) -> throwable != null || !isHttpSuccess(response.statusCode()))
                .withMaxDuration(Duration.ofSeconds(configuration.getCallbackRetryMaxDuration()))
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .onRetry(ctx -> logger.warn("Callback retry attempt:{}, last status:{}, last error:{}",
                                            ctx.getAttemptCount(),
                                            ctx.getLastResult().statusCode(),
                                            ctx.getLastFailure()));
        Failsafe.with(retryPolicy)
                .with(executor)
                .getStageAsync(() -> httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()))
                .handleAsync((resp, t) -> {
                    if (t != null) {
                        logger.error("Unable to send callback.", t);
                    } else {
                        logger.info("Callback sent, response status: {}.", resp.statusCode());
                    }
                    return null;
                });
    }

    private String getPodName(String environmentId) {
        return "pnc-ba-pod-" + environmentId;
    }

    private String getServiceName(String environmentId) {
        return "pnc-ba-service-" + environmentId;
    }

    private String getSshServiceName(String environmentId) {
        return "pnc-ba-ssh-" + environmentId;
    }

    private void putMdcToResultMap(Map<String, String> result, Map<String, String> mdcMap, String mdcKey) throws DriverException {
        if (mdcMap == null) {
            throw new DriverException("Missing MDC map.");
        }
        if (mdcMap.get(mdcKey) != null) {
            result.put("log-" + mdcKey, mdcMap.get(mdcKey));
        } else {
            throw new DriverException("Missing MDC value " + mdcKey);
        }
    }

    private List<Request.Header> getHeaders() {
        List<Request.Header> headers = new ArrayList<>();
        headers.add(new Request.Header(Headers.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON));
        if (webToken.getRawToken() != null) {
            headers.add(new Request.Header(Headers.AUTHORIZATION_STRING, "Bearer " + webToken.getRawToken()));
        }
        headersFromMdc(headers, MDCHeaderKeys.REQUEST_CONTEXT);
        headersFromMdc(headers, MDCHeaderKeys.PROCESS_CONTEXT);
        headersFromMdc(headers, MDCHeaderKeys.TMP);
        headersFromMdc(headers, MDCHeaderKeys.EXP);
        return headers;
    }

    private void headersFromMdc(List<Request.Header> headers, MDCHeaderKeys headerKey) {
        String mdcValue = MDC.get(headerKey.getMdcKey());
        if (!Strings.isEmpty(mdcValue)) {
            headers.add(new Request.Header(headerKey.getHeaderName(), mdcValue));
        }
    }

    private String builderPodMemory(int defaultBuilderPodMemory, String builderPodMemoryOverride) {
        double builderPodMemory = defaultBuilderPodMemory;
        if (!Strings.isEmpty(builderPodMemoryOverride)) {
            try {
                double parsedPodMemory = Double.parseDouble(builderPodMemoryOverride);
                if (parsedPodMemory > 0) {
                    builderPodMemory = parsedPodMemory;
                    logger.info("Using override for builder pod memory size: {}", builderPodMemoryOverride);
                }
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Failed to parse memory size '" + builderPodMemoryOverride, ex);
            }
        }
        return ((int) Math.ceil(builderPodMemory * 1024)) + "Mi";
    }

    private <T> T createModelNode(String resourceDefinition, Map<String, String> properties, Class<T> clazz) {
        String definition = StringSubstitutor.replace(resourceDefinition, properties, "${", "}");

        if (logger.isTraceEnabled()) {
            logger.trace("Node definition: {}", secureLog(definition));
        }

        try {
            return mapper.readValue(definition, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private static final Pattern SECURE_LOG_PATTERN = Pattern
            .compile("\"name\":\\s*\"accessToken\",\\s*\"value\":\\s*\"\\p{Print}+\"");

    static String secureLog(String message) {
        return SECURE_LOG_PATTERN.matcher(message)
                .replaceAll("\"name\": \"accessToken\",\n" + "            \"value\": \"***\"");
    }

    private Map<String, String> mdcToMap() throws DriverException {
        Map<String, String> result = new HashMap<>();
        Map<String, String> mdcMap = MDC.getCopyOfContextMap();
        putMdcToResultMap(result, mdcMap, MDCKeys.PROCESS_CONTEXT_KEY);
        putMdcToResultMap(result, mdcMap, MDCKeys.TMP_KEY);
        putMdcToResultMap(result, mdcMap, MDCKeys.EXP_KEY);
        putMdcToResultMap(result, mdcMap, MDCKeys.USER_ID_KEY);
        return result;
    }

    private boolean isHttpSuccess(int responseCode) {
        return responseCode >= 200 && responseCode < 300;
    }
}
