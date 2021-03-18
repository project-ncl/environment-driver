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

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.openshift.client.DefaultOpenShiftClient;
import io.fabric8.openshift.client.OpenShiftClient;
import io.undertow.util.Headers;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.apache.commons.text.StringSubstitutor;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.pnc.api.constants.MDCKeys;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.buildagent.common.StringUtils;
import org.jboss.pnc.common.Strings;
import org.jboss.pnc.common.constants.MDCHeaderKeys;
import org.jboss.pnc.environmentdriver.dto.CreateRequest;
import org.jboss.pnc.environmentdriver.dto.EnvironmentCreationCompleted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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

    /**
     * Parameter specifying override for the builder pod memory size.
     */
    private static final String BUILDER_POD_MEMORY = "BUILDER_POD_MEMORY";

    @Inject
    ManagedExecutor executor;

    @Inject
    JsonWebToken webToken;

    @Inject
    OpenshiftEnvironmentDriverModuleConfig environmentConfiguration;

    @Inject
    ObjectMapper mapper;

    @Inject
    ActiveMonitors activeMonitors;

    @ConfigProperty(name = "environment-driver.openshift.pod")
    private String podDefinition;

    @ConfigProperty(name = "environment-driver.openshift.service")
    private String serviceDefinition;

    private OpenShiftClient client;
    private java.net.http.HttpClient httpClient;

    @PostConstruct
    void init() {
        Config config = new ConfigBuilder()
                .withNamespace(environmentConfiguration.getPncNamespace())
                .withMasterUrl(environmentConfiguration.getRestEndpointUrl())
                .withOauthToken(environmentConfiguration.getRestAuthToken())
                .build();
        client = new DefaultOpenShiftClient(config);

        httpClient = java.net.http.HttpClient.newBuilder()
                .executor(executor)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public CompletionStage<CreateResponse> create(CreateRequest createRequest) throws DriverException {

        Request completionCallback = createRequest.getCompletionCallback();

        String buildIdBase64 = createRequest.getBuildIdBase64();
        String podName = getPodName(buildIdBase64);
        String serviceName = "pnc-ba-service-" + buildIdBase64;

        Pod existingPod = client.pods().withName(podName).get();
        if (existingPod != null) {
            //do we need this at all? Yes, it makes the endpoint idempotent
            //if this driver service dies while waiting for ready state (to send a callback),
            // the invoker will request the same env again
            //TODO
            //schedule ready callback
            //return already requested
        }

        Map<String, String> environmentVariables = new HashMap<>();

        final String buildAgentHost = environmentConfiguration.getBuildAgentHost();

        boolean proxyActive = !StringUtils.isEmpty(environmentConfiguration.getProxyServer())
                && !StringUtils.isEmpty(environmentConfiguration.getProxyPort());

        environmentVariables.put("image", createRequest.getImageId());
        environmentVariables.put("firewallAllowedDestinations", environmentConfiguration.getFirewallAllowedDestinations());
        environmentVariables.put("isHttpActive", Boolean.toString(proxyActive).toLowerCase());
        environmentVariables.put("proxyServer", environmentConfiguration.getProxyServer());
        environmentVariables.put("proxyPort", environmentConfiguration.getProxyPort());
        environmentVariables.put("nonProxyHosts", environmentConfiguration.getNonProxyHosts());

        environmentVariables.put("AProxDependencyUrl", repositorySession.getConnectionInfo().getDependencyUrl());
        environmentVariables.put("AProxDeployUrl", repositorySession.getConnectionInfo().getDeployUrl());

        environmentVariables.put("build-agent-host", buildAgentHost);
        environmentVariables.put("containerPort", environmentConfiguration.getContainerPort());
        environmentVariables.put("buildContentId", repositorySession.getBuildRepositoryId());
        environmentVariables.put("accessToken", webToken.getRawToken());

        environmentVariables.putAll(mdcToEnvVariables());
        environmentVariables.put("resourcesMemory", builderPodMemory(
                environmentConfiguration.getBuilderPodMemory(),
                podMemoryOverride));

        String buildAgentContextPath = "pnc-ba-" + buildIdBase64;

        // variables specific to to this pod (retry)
        environmentVariables.put("pod-name", podName);
        environmentVariables.put("service-name", serviceName);
        environmentVariables.put("ssh-service-name", "pnc-ba-ssh-" + buildIdBase64);
        environmentVariables.put("route-name", "pnc-ba-route-" + buildIdBase64);
        environmentVariables.put("route-path", "/" + buildAgentContextPath);
        environmentVariables.put("buildAgentContextPath", "/" + buildAgentContextPath);

        CompletableFuture<Pod> podFuture = CompletableFuture.supplyAsync(() -> {
                Pod podCreationModel = createModelNode(
                    podDefinition,
                    environmentVariables,
                    Pod.class);
                //TODO check if the pod exists (this could be a retry request)
                return client.pods().create(podCreationModel);
            }, executor);

        CompletableFuture<Service> serviceFuture = CompletableFuture.supplyAsync(() -> {
                Service serviceCreationModel = createModelNode(
                    serviceDefinition,
                    environmentVariables,
                    Service.class);
                //TODO check if the service exists (this could be a retry request)
                return client.services().create(serviceCreationModel);
            }, executor
        );

        CompletableFuture<Void> podAndServiceFuture = CompletableFuture.allOf(podFuture, serviceFuture);

        podAndServiceFuture.handleAsync((r, t) -> {
            if (t != null) {
                startMonitor(serviceName, podName);
            }
            callback(
                        completionCallback,
                        new EnvironmentCreationCompleted(
                                getEnvironmentBaseUrl(service),
                                environmentConfiguration.getWorkingDirectory(),
                                completionCallback.getAttachment(),
                                t
                        ));
                return null;
             } , executor);

        return podAndServiceFuture.thenApplyAsync((nul) -> new CreateResponse());
    }

    private String getPodName(String buildIdBase64) {
        return "pnc-ba-pod-" + buildIdBase64;
    }

    //should hit the same node to cancel the monitor
    //TODO should cancel clean up potentially created resources ?
    //Or should we leave to the invoker and always call destroy once the create has been called.
    public void cancel(String buildIdBase64) {
        activeMonitors.cancel(getPodName(buildIdBase64));
    }

    private void startMonitor(String serviceName, String podName) {
        //TODO what to do with potentially active monitors ?
        //activeMonitors.cancel(podName);

        CompletableFuture<Void> serviceRunning = isServiceRunning(serviceName, 15, 500); //TODO configurable
        activeMonitors.add(podName, serviceRunning);

        CompletableFuture<Void> podRunning = isPodRunning(podName, 15, 1000); //TODO configurable
        activeMonitors.add(podName, podRunning);

        CompletableFuture.allOf(podRunning, serviceRunning)
                .thenRunAsync(() -> {
                    CompletableFuture<Void> pingFuture = ping(getEnvironmentBaseUrl() + );
                    activeMonitors.add(podName, pingFuture);
                })
                .handleAsync((nul, throwable) -> {
                    activeMonitors.remove(podName);
                    if (throwable instanceof CancellationException) {
                        //TODO respond canceled
                    }
                    callback(callbackRaquest, new EnvironmentCreationCompleted());
                    return null;
                });

        //TODO in post-build step (destroy env).
        //initDebug();
    }


    private URI getEnvironmentBaseUrl(Service service) {
        return null; //TODO
    }

    /**
     * Check if pod is in running state. If pod is in one of the failure statuses (as specified in POD_FAILED_STATUSES,
     * {@link CompletableFuture} is compelted with {@link UnableToStartException}
     *
     * @return boolean: is pod running?
     */
    //TODO add readiness probe to the pod
    private CompletableFuture<Void> isPodRunning(String podName, int maxRetries, int retryDelayMillis) {
        //TODO should we use events
        // https://docs.openshift.com/container-platform/4.7/rest_api/metadata_apis/event-core-v1.html#apiv1namespacesnamespaceeventsname
        // https://github.com/fabric8io/kubernetes-client/blob/master/doc/CHEATSHEET.md#pods

        RetryPolicy<String> retryPolicy = new RetryPolicy<String>()
                .withMaxRetries(maxRetries)
                .withBackoff(retryDelayMillis, 10000, ChronoUnit.MILLIS) //TODO configurable max delay
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

    private CompletableFuture<Void> isServiceRunning(String serviceName, int maxRetries, int retryDelayMillis) {
        RetryPolicy<Object> retryPolicy = new RetryPolicy<>()
                .withMaxRetries(maxRetries)
                .withBackoff(retryDelayMillis, 10000, ChronoUnit.MILLIS) //TODO configurable max delay
                .onRetry(ctx -> logger.warn("Retry attempt:{}, last error:{}",
                                            ctx.getAttemptCount(),
                                            ctx.getLastFailure()));
        return Failsafe.with(retryPolicy)
                .with(executor)
                .runAsync(() -> {
                    Service service = client.services().withName(serviceName).get();
                    String clusterIP = service.getSpec().getClusterIP();
                    if (clusterIP == null) {
                        throw new DriverException("Service " + serviceName + " is not running.");
                    } else {
                        logger.info("Service {} ip: {}.",serviceName, clusterIP);
                    }
                });
    }

    private CompletableFuture<Void> ping(String serviceName, int maxRetries, int retryDelayMillis) {
        HttpRequest request;
        RetryPolicy<HttpResponse> retryPolicy = new RetryPolicy<HttpResponse>()
                .handleIf((response,throwable) -> throwable != null || !isHttpSuccess(response.statusCode()))
                .withMaxRetries(10) //TODO
                .withBackoff(500, 10000, ChronoUnit.MILLIS) //TODO configurable max delay
                .onRetry(ctx -> logger.warn("Retry attempt:{}, last status:{}, last error:{}",
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


    private String getInternalEndpointUrl() {
        return "http://" + service.getSpec().getClusterIP() + "/" + buildAgentContextPath + "/"
                + environmentConfiguration.getBuildAgentBindPath();
    }

    private boolean isInternalServletAvailable() {
        //TODO
    }

    private void callback(Request callback, EnvironmentCreationCompleted environmentCreationCompleted) {
        String body = mapper.writeValueAsString(environmentCreationCompleted);
        callback.getAttachment();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(callback.getUri())
                .method(callback.getMethod().name(), HttpRequest.BodyPublishers.ofString(body))
                .timeout();
        callback.getHeaders().forEach(h -> builder.header(h.getName(), h.getValue()));
        HttpRequest request = builder.build();

        RetryPolicy<HttpResponse> retryPolicy = new RetryPolicy<HttpResponse>()
                .handleIf((response,throwable) -> throwable != null || !isHttpSuccess(response.statusCode()))
                .withMaxRetries(10) //TODO
                .withBackoff(500, 10000, ChronoUnit.MILLIS) //TODO configurable max delay
                .onRetry(ctx -> logger.warn("Retry attempt:{}, last status:{}, last error:{}",
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

    private void mdcToMap(Map<String, String> result, Map<String, String> mdcMap, String mdcKey) throws DriverException {
        if (mdcMap == null) {
            throw new DriverException("Missing MDC map.");
        }
        if (mdcMap.get(mdcKey) != null) {
            result.put("log-" + mdcKey, mdcMap.get(mdcKey));
        } else {
            throw new DriverException("Missing MDC value " + mdcKey);
        }
    }



    private boolean isHttpSuccess(int responseCode) {
        return responseCode >= 200 && responseCode < 300;
    }

    private Set<Request.Header> getHeaders() {
        Set<Request.Header> headers = new HashSet<>();
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

    private void headersFromMdc(Set<Request.Header> headers, MDCHeaderKeys headerKey) {
        String mdcValue = MDC.get(headerKey.getMdcKey());
        if (!Strings.isEmpty(mdcValue)) {
            headers.add(new Request.Header(headerKey.getHeaderName(), mdcValue));
        }
    }

    private String builderPodMemory(int defaultBuilderPodMemory, Optional<String> builderPodMemoryOverride) {
        double builderPodMemory = defaultBuilderPodMemory;
        if (builderPodMemoryOverride.isPresent()) {
            try {
                builderPodMemory = Double.parseDouble(builderPodMemoryOverride.get());
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Failed to parse memory size '" + builderPodMemoryOverride, ex);
            }
            logger.info("Using override for builder pod memory size: {}", builderPodMemoryOverride);
        }
        return ((int) Math.ceil(builderPodMemory * 1024)) + "Mi";
    }

    private <T> T createModelNode(String resourceDefinition, Map<String, String> runtimeProperties, Class<T> clazz) {
        Properties properties = new Properties();
        properties.putAll(runtimeProperties);
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

    private Map<String, String> mdcToEnvVariables() throws DriverException {
        Map<String, String> result = new HashMap<>();
        Map<String, String> mdcMap = MDC.getCopyOfContextMap();
        mdcToMap(result, mdcMap, MDCKeys.PROCESS_CONTEXT_KEY);
        mdcToMap(result, mdcMap, MDCKeys.TMP_KEY);
        mdcToMap(result, mdcMap, MDCKeys.EXP_KEY);
        mdcToMap(result, mdcMap, MDCKeys.USER_ID_KEY);
        return result;
    }

}
