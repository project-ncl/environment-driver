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
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodList;
import io.fabric8.kubernetes.api.model.Quantity;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceList;
import io.fabric8.kubernetes.api.model.ServicePort;
import io.fabric8.openshift.api.model.Route;
import io.fabric8.openshift.client.OpenShiftClient;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.constants.MDCHeaderKeys;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCompleteResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResult;
import org.jboss.pnc.common.Random;
import org.jboss.pnc.common.Strings;
import org.jboss.pnc.environmentdriver.runtime.ApplicationLifecycle;
import org.jboss.pnc.pncmetrics.GaugeMetric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_FAILED_KEY;
import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_FAILED_REASON_KEY;
import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_SUCCESS_KEY;

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
            "ImagePullBackOff", "Error", "InvalidImageName", "ContainerCannotRun" };

    @Inject
    @UserLogger
    Logger userLogger;

    @Inject
    JsonWebToken webToken;

    @Inject
    ManagedExecutor executor;

    @Inject
    ObjectMapper jsonMapper;

    @Inject
    Configuration configuration;

    @Inject
    ActiveMonitors activeMonitors;

    @Inject
    OpenShiftClient openShiftClient;

    @Inject
    java.net.http.HttpClient httpClient;

    @Inject
    ApplicationLifecycle lifecycle;

    ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    private Optional<GaugeMetric> gaugeMetric = Optional.empty(); // TODO

    /**
     * Calls the Openshift API to create required resources. Method does not wait for the resources to become available,
     * when the resources are available the callback to the invoker is executed. If the resource creation requests fail,
     * the CompletionStage is completed exceptionally. To keep the required state minimal, the retries should be handled
     * externally.
     *
     * @return CompletionStage which is completed when all required requests to the Openshift complete.
     */
    public CompletionStage<EnvironmentCreateResponse> create(EnvironmentCreateRequest environmentCreateRequest) {
        if (lifecycle.isShuttingDown()) {
            throw new StoppingException();
        }
        String environmentId = environmentCreateRequest.getEnvironmentLabel() + "-" + Random.randString(6);

        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);

        String rawWebToken = webToken.getRawToken();

        Map<String, String> environmentVariables = new HashMap<>();

        boolean proxyActive = configuration.getProxyServer().isPresent() && configuration.getProxyPort().isPresent();

        environmentVariables.put("image", environmentCreateRequest.getImageId());
        environmentVariables.put("firewallAllowedDestinations", configuration.getFirewallAllowedDestinations());
        environmentVariables
                .put("allowedHttpOutgoingDestinations", configuration.getAllowedHttpOutgoingDestinations().orElse(""));
        environmentVariables.put("isHttpActive", Boolean.toString(proxyActive).toLowerCase());
        environmentVariables.put("proxyServer", configuration.getProxyServer().orElse(""));
        environmentVariables.put("proxyPort", configuration.getProxyPort().orElse(""));
        environmentVariables.put("nonProxyHosts", configuration.getNonProxyHosts().orElse(""));

        environmentVariables.put("AProxDependencyUrl", environmentCreateRequest.getRepositoryDependencyUrl());
        environmentVariables.put("AProxDeployUrl", environmentCreateRequest.getRepositoryDeployUrl());

        environmentVariables.put("containerPort", configuration.getBuildAgentContainerPort());
        environmentVariables.put("buildContentId", environmentCreateRequest.getRepositoryBuildContentId());
        environmentVariables.put("accessToken", rawWebToken);

        try {
            environmentVariables.putAll(mdcToMap());
        } catch (DriverException e) {
            return CompletableFuture.failedFuture(e);
        }

        environmentVariables.put(
                "resourcesMemory",
                builderPodMemory(configuration.getBuilderPodMemory(), environmentCreateRequest.getPodMemoryOverride()));

        String buildAgentContextPath = getBuildAgentContextPath(environmentId);
        environmentVariables.put("environment-label", environmentCreateRequest.getEnvironmentLabel());
        environmentVariables.put("pod-name", podName);
        environmentVariables.put("service-name", serviceName);
        environmentVariables.put("buildAgentContextPath", buildAgentContextPath);

        String sshPassword;
        if (environmentCreateRequest.isAllowSshDebug()) {
            sshPassword = RandomStringUtils.randomAlphanumeric(10);
            environmentVariables.put("workerUserPassword", sshPassword);
        } else {
            sshPassword = "";
        }

        CompletableFuture<Pod> podRequested = CompletableFuture.supplyAsync(() -> {
            Pod podCreationModel = createModelNode(configuration.getPodDefinition(), environmentVariables, Pod.class);
            return openShiftClient.pods().create(podCreationModel);
        }, executor);

        CompletableFuture<Service> serviceRequested = CompletableFuture.supplyAsync(() -> {
            Service serviceCreationModel = createModelNode(
                    configuration.getServiceDefinition(),
                    environmentVariables,
                    Service.class);
            return openShiftClient.services().create(serviceCreationModel);
        }, executor);

        CompletableFuture<Void> podAndServiceRequested = CompletableFuture.allOf(podRequested, serviceRequested);

        return podAndServiceRequested.thenApplyAsync((nul) -> {
            startMonitor(
                    serviceName,
                    buildAgentContextPath,
                    podName,
                    environmentCreateRequest.getCompletionCallback(),
                    sshPassword);
            return new EnvironmentCreateResponse(environmentId, getCancelRequest(environmentId, rawWebToken));
        }, executor);
    }

    private Request getCancelRequest(String environmentId, String rawWebToken) {
        return Request.builder()
                .method(Request.Method.PUT)
                .uri(
                        URI.create(
                                Strings.stripEndingSlash(configuration.getThisServiceBaseUrl()) + "/cancel/"
                                        + environmentId))
                .headers(getHeaders(rawWebToken))
                .build();
    }

    public CompletionStage<EnvironmentCompleteResponse> enableDebug(String environmentId) {
        Map<String, String> serviceEnvVariables = new HashMap<>();
        serviceEnvVariables.put("pod-name", getPodName(environmentId));
        serviceEnvVariables.put("ssh-service-name", getSshServiceName(environmentId));

        Map<String, String> routeEnvVariables = new HashMap<>();
        routeEnvVariables.put("route-name", getRouteName(environmentId));
        routeEnvVariables.put("route-path", getBuildAgentContextPath(environmentId));
        routeEnvVariables.put("service-name", getServiceName(environmentId));
        routeEnvVariables.put("build-agent-host", configuration.getBuildAgentHost());

        // Enable ssh forwarding and complete with the port to which ssh is forwarded
        return CompletableFuture.supplyAsync(() -> {
            Service serviceCreationModel = createModelNode(
                    configuration.getSshServiceDefinition(),
                    serviceEnvVariables,
                    Service.class);
            Service sshService = openShiftClient.services().create(serviceCreationModel);
            return sshService.getSpec()
                    .getPorts()
                    .stream()
                    .filter(m -> m.getName().equals(configuration.getSshServicePortName()))
                    .findAny()
                    .orElseThrow(() -> new RuntimeException("No ssh service in response! Service data: " + sshService))
                    .getNodePort();
        }, executor).thenApplyAsync(sshPort -> {
            Route routeCreationModel = createModelNode(
                    configuration.getRouteDefinition(),
                    routeEnvVariables,
                    Route.class);
            Route route = openShiftClient.routes().create(routeCreationModel);
            String sshHost = route.getSpec().getHost();
            return new InetSocketAddress(sshHost, sshPort);
        }, executor)
                .thenComposeAsync(this::pingSsh)
                .thenApplyAsync(
                        socketAddr -> new EnvironmentCompleteResponse(socketAddr.getHostName(), socketAddr.getPort()));
    }

    private CompletableFuture<InetSocketAddress> pingSsh(InetSocketAddress inetSocketAddress) {
        RetryPolicy<InetSocketAddress> retryPolicy = new RetryPolicy<InetSocketAddress>()
                .withMaxDuration(Duration.ofSeconds(configuration.getSshPingRetryDuration()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(500, 2000, ChronoUnit.MILLIS) // don't wait too long, the response is waiting
                .onSuccess(ctx -> logger.info("SSH ping success."))
                .onRetry(
                        ctx -> logger.warn(
                                "Ssh ping retry attempt: #{}, last error: [{}]",
                                ctx.getAttemptCount(),
                                ctx.getLastFailure()))
                .onFailure(ctx -> logger.error("Unable to ping ssh service: {}.", ctx.getFailure().getMessage()))
                .onAbort(e -> logger.warn("SSH ping ping aborted: {}.", e.getFailure().getMessage()));
        return Failsafe.with(retryPolicy).with(executor).getAsync(() -> {
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
     * Method will try its best to destroy the environment. Fire and forget operation.
     */
    public void destroy(String environmentId) {
        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);
        activeMonitors.cancel(podName);

        // delete service
        RetryPolicy<String> serviceRetryPolicy = getDestroyRetryPolicy(serviceName);
        Failsafe.with(serviceRetryPolicy).with(executor).runAsync(() -> {
            Service service = openShiftClient.services().withName(serviceName).get();
            if (service != null) {
                if (openShiftClient.services().delete(service)) {
                    logger.info("Service {} deleted.", serviceName);
                } else {
                    logger.warn("Service {} was not deleted.", serviceName);
                }
            } else {
                logger.warn("Service {} does not exists.", serviceName);
            }
        });
        // delete pod
        RetryPolicy<String> podRetryPolicy = getDestroyRetryPolicy(podName);
        Failsafe.with(podRetryPolicy).with(executor).runAsync(() -> {
            Pod pod = openShiftClient.pods().withName(podName).get();
            if (pod != null) {
                if (openShiftClient.pods().delete(pod)) {
                    logger.info("Pod {} deleted.", podName);
                } else {
                    logger.warn("Pod {} was not deleted.", podName);
                }
            } else {
                logger.warn("Pod {} does not exists.", podName);
            }
        });
    }

    private RetryPolicy<String> getDestroyRetryPolicy(String resourceName) {
        return new RetryPolicy<String>().withMaxDuration(Duration.ofSeconds(configuration.getDestroyRetryDuration()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(1000, 10000, ChronoUnit.MILLIS)
                .onSuccess(ctx -> logger.info("Destroy {} success.", resourceName))
                .onRetry(
                        ctx -> logger.warn(
                                "Destroy {} retry attempt #{}, last error: [{}].",
                                resourceName,
                                ctx.getAttemptCount(),
                                ctx.getLastFailure().getMessage()))
                .onFailure(
                        ctx -> logger.error("Unable to destroy {}: {}.", resourceName, ctx.getFailure().getMessage()))
                .onAbort(e -> logger.warn("Destroy {} aborted: {}.", resourceName, e.getFailure().getMessage()));
    }

    /**
     * Method will try its best to destroy all the environments created from given environmentName. Fire and forget
     * operation.
     */
    public void destroyAll(String environmentLabel) {
        // delete service
        RetryPolicy<String> servicesRetryPolicy = getDestroyRetryPolicy("services-of-" + environmentLabel);
        Failsafe.with(servicesRetryPolicy).with(executor).runAsync(() -> {
            ServiceList serviceList = openShiftClient.services().withLabel("environment", environmentLabel).list();
            if (serviceList != null) {
                if (openShiftClient.services().delete(serviceList.getItems())) {
                    logger.info("Services {} deleted.", getItemNames(serviceList.getItems()));
                } else {
                    logger.warn("Services {} were not deleted.", getItemNames(serviceList.getItems()));
                }
            } else {
                logger.warn("No services found by label {}.", environmentLabel);
            }
        });
        // delete pod
        RetryPolicy<String> podsRetryPolicy = getDestroyRetryPolicy("pods-of-" + environmentLabel);
        Failsafe.with(podsRetryPolicy).with(executor).runAsync(() -> {
            PodList podList = openShiftClient.pods().withLabel("environment", environmentLabel).list();
            if (podList != null) {
                if (openShiftClient.pods().delete(podList.getItems())) {
                    logger.info("Pods {} deleted.", getItemNames(podList.getItems()));
                } else {
                    logger.warn("Pods {} were not deleted.", getItemNames(podList.getItems()));
                }
            } else {
                logger.warn("No pods found by label {}.", environmentLabel);
            }
        });
    }

    private void startMonitor(
            String serviceName,
            String buildAgentContextPath,
            String podName,
            Request completionCallback,
            String sshPassword) {
        lifecycle.addActiveOperation();
        CompletableFuture<URI> serviceRunning = isServiceRunning(serviceName);
        activeMonitors.add(podName, serviceRunning);

        CompletableFuture<Void> podRunning = isPodRunning(podName);
        activeMonitors.add(podName, podRunning);

        CompletableFuture.allOf(podRunning, serviceRunning).thenComposeAsync((nul) -> {
            URI serviceBaseUri = serviceRunning.join(); // future already completed (allOff)
            String serviceUriWithContext = serviceBaseUri + buildAgentContextPath;
            CompletableFuture<HttpResponse<String>> pingFuture = pingBuildAgent(serviceUriWithContext);
            activeMonitors.add(podName, pingFuture);
            return pingFuture.thenApply((ignoreResponse) -> URI.create(serviceUriWithContext));
        }).handleAsync((serviceUriWithContext, throwable) -> {
            logger.debug("Completing monitor for pod: {}", podName);
            activeMonitors.remove(podName);
            CompletableFuture<HttpResponse<String>> callback;
            if (throwable != null) {
                if (throwable instanceof CancellationException) {
                    callback = callback(completionCallback, EnvironmentCreateResult.cancelled());
                } else {
                    callback = callback(completionCallback, EnvironmentCreateResult.failed(throwable));
                    gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_KEY));
                }
            } else {
                EnvironmentCreateResult environmentCreateResult = EnvironmentCreateResult
                        .success(serviceUriWithContext, configuration.getWorkingDirectory(), sshPassword);
                callback = callback(completionCallback, environmentCreateResult);
                gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_SUCCESS_KEY));
            }
            callback.handle((r, t) -> {
                if (t != null) {
                    logger.error("Unable to send completion callback.", t);
                }
                lifecycle.removeActiveOperation();
                return null;
            });
            return null;
        });
    }

    /**
     * Tries to convert the Quantity value into the same units
     *
     * If the value unit is blank, return the value itself
     * 
     * If the value unit is Gi / Mi, return the value in Gi unit
     * 
     * If the value unit is m, return the original value / 1024
     *
     * @param quantity quantity to convert
     * @return converted unit
     * @throws RuntimeException if it does not know how to convert the unit
     */
    private static double convertQuantity(Quantity quantity) {
        String unit = quantity.getFormat();
        double value = Double.parseDouble(quantity.getAmount());

        switch (unit) {
            case "":
            case "Gi":
                return value;
            case "Mi":
            case "m":
                return value / 1024;
            default:
                throw new RuntimeException("Don't know how to convert the unit " + quantity);
        }
    }

    private double calculateResourceUsedByPod(String podName, String resourceType) {
        return openShiftClient.top()
                .pods()
                .metrics(openShiftClient.pods().withName(podName).get().getMetadata().getNamespace(), podName)
                .getContainers()
                .stream()
                .mapToDouble(containerMetrics -> convertQuantity(containerMetrics.getUsage().get(resourceType)))
                .sum();
    }

    private double calculateAvailableResource(String resourceType) {
        String identifier = "limits." + resourceType;
        return openShiftClient.resourceQuotas()
                .list()
                .getItems()
                .stream()
                .findFirst() // Only consider the first quota, we generally only use one!
                .map(
                        resourceQuota -> convertQuantity(resourceQuota.getStatus().getHard().get(identifier))
                                - convertQuantity(resourceQuota.getStatus().getUsed().get(identifier)))
                .orElse(0.0);
    }

    /**
     * Check if pod is in running state. If pod is in one of the failure statuses (as specified in POD_FAILED_STATUSES,
     * {@link CompletableFuture} is completed with {@link UnableToStartException}
     *
     * @return boolean: is pod running?
     */
    private CompletableFuture<Void> isPodRunning(String podName) {
        RetryPolicy<String> retryPolicy = new RetryPolicy<String>()
                .withMaxDuration(Duration.ofSeconds(configuration.getPodRunningWaitFor()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(1000, 5000, ChronoUnit.MILLIS)
                .abortOn(UnableToStartException.class)
                .onSuccess(ctx -> userLogger.info("Pod is running: {}.", podName))
                .onRetry(
                        ctx -> userLogger.warn(
                                "Pod {} running retry attempt #{}; Requested resources: {}GB {}cpu;"
                                        + "Available resources: {}GB {}cpu; Last error: [{}].",
                                podName,
                                ctx.getAttemptCount(),
                                String.format("%.2f", calculateResourceUsedByPod(podName, "memory")),
                                String.format("%.0f", calculateResourceUsedByPod(podName, "cpu")),
                                String.format("%.2f", calculateAvailableResource("memory")),
                                String.format("%.0f", calculateAvailableResource("cpu")),
                                ctx.getLastFailure().getMessage()))
                .onFailure(
                        ctx -> userLogger.error("Unable to start pod {}: {}.", podName, ctx.getFailure().getMessage()))
                .onAbort(
                        e -> userLogger
                                .warn("IsPodRunning aborted. Pod {}: {}.", podName, e.getFailure().getMessage()));

        return Failsafe.with(retryPolicy).with(executor).runAsync(() -> {
            Pod pod = openShiftClient.pods().withName(podName).get();
            String podStatus = pod.getStatus().getPhase();
            logger.debug("Pod {} status: {}", pod.getMetadata().getName(), podStatus);
            if (Arrays.asList(POD_FAILED_STATUSES).contains(podStatus)) {
                if (podStatus.toLowerCase().contains("image")) {
                    userLogger.warn(
                            "The builder pod failed to start because it was not able "
                                    + "to download the builder image (this could be due to issues with the builder "
                                    + "images registry, or a misconfiguration of the builder image name).");
                }
                gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_REASON_KEY + "." + podStatus));
                throw new UnableToStartException("Pod failed with status: " + podStatus);
            }
            boolean isRunning = "Running".equals(pod.getStatus().getPhase());
            if (isRunning) {
                logger.debug("Pod running: {}.", pod.getMetadata().getName());
            } else {
                throw new DriverException("Pod is not running.");
            }
        });
    }

    private CompletableFuture<URI> isServiceRunning(String serviceName) {
        RetryPolicy<Object> retryPolicy = new RetryPolicy<>()
                .withMaxDuration(Duration.ofSeconds(configuration.getServiceRunningWaitFor()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .onRetry(
                        ctx -> userLogger.warn(
                                "Is service running retry attempt:{}, last error:{}",
                                ctx.getAttemptCount(),
                                ctx.getLastFailure()));
        return Failsafe.with(retryPolicy).with(executor).getAsync(() -> {
            Service service = openShiftClient.services().withName(serviceName).get();
            String clusterIP = service.getSpec().getClusterIP();
            List<ServicePort> ports = service.getSpec().getPorts();
            if (ports == null || ports.size() == 0) {
                throw new DriverException("Service " + serviceName + " has no mapped ports.");
            }
            Integer clusterPort = ports.get(0).getPort(); // get the first port, there should be one only
            if (clusterIP == null) {
                throw new DriverException("Service " + serviceName + " is not running.");
            } else {
                userLogger.info("Service up: {} ip: {}.", serviceName, clusterIP);
                return URI.create(configuration.getBuildAgentServiceScheme() + "://" + clusterIP + ":" + clusterPort);
            }
        });
    }

    private CompletableFuture<HttpResponse<String>> pingBuildAgent(String serviceUriWithContext) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(serviceUriWithContext + configuration.getBuildAgentPingPath()))
                .method(Request.Method.HEAD.name(), HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(configuration.getHttpClientRequestTimeout()));
        HttpRequest request = builder.build();
        RetryPolicy<HttpResponse<String>> retryPolicy = new RetryPolicy<HttpResponse<String>>()
                .withMaxDuration(Duration.ofSeconds(configuration.getBuildAgentRunningWaitFor()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(500, 2000, ChronoUnit.MILLIS)
                .onSuccess(
                        ctx -> logger.info("BuildAgent responded, response status: {}.", ctx.getResult().statusCode()))
                .onRetry(ctx -> {
                    String lastError;
                    if (ctx.getLastFailure() != null) {
                        lastError = ctx.getLastFailure().getMessage();
                    } else {
                        lastError = "";
                    }
                    Integer lastStatus;
                    if (ctx.getLastResult() != null) {
                        lastStatus = ctx.getLastResult().statusCode();
                    } else {
                        lastStatus = null;
                    }
                    logger.warn(
                            "BuildAgent ping retry attempt #{}, last error: [{}], last status: [{}].",
                            ctx.getAttemptCount(),
                            lastError,
                            lastStatus);
                })
                .onFailure(ctx -> logger.error("Unable to ping BuildAgent: {}.", ctx.getFailure().getMessage()))
                .onAbort(e -> logger.warn("BuildAgent ping aborted: {}.", e.getFailure().getMessage()));

        logger.info("About to ping BuildAgent {}.", request.uri());
        return Failsafe.with(retryPolicy)
                .with(executor)
                .getStageAsync(
                        () -> httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                                .thenApply(validateResponse()));
    }

    private CompletableFuture<HttpResponse<String>> callback(
            Request callback,
            EnvironmentCreateResult environmentCreateResult) {
        String body;
        try {
            body = jsonMapper.writeValueAsString(environmentCreateResult);
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
                .withMaxDuration(Duration.ofSeconds(configuration.getCallbackRetryDuration()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(500, 5000, ChronoUnit.MILLIS)
                .onSuccess(
                        ctx -> logger.info(
                                "Callback sent to: {}, response status: {}.",
                                callback.getUri(),
                                ctx.getResult().statusCode()))
                .onRetry(ctx -> {
                    String lastError;
                    if (ctx.getLastFailure() != null) {
                        lastError = ctx.getLastFailure().getMessage();
                    } else {
                        lastError = "";
                    }
                    Integer lastStatus;
                    if (ctx.getLastResult() != null) {
                        lastStatus = ctx.getLastResult().statusCode();
                    } else {
                        lastStatus = null;
                    }
                    logger.warn(
                            "Callback retry attempt #{}, last error: [{}], last status: [{}].",
                            ctx.getAttemptCount(),
                            lastError,
                            lastStatus);
                })
                .onFailure(ctx -> logger.error("Unable to send callback to: " + callback.getUri()))
                .onAbort(e -> logger.warn("Callback aborted: {}.", e.getFailure().getMessage()));
        logger.debug(
                "About to callback: {} {}. With headers: {}.",
                callback.getMethod(),
                callback.getUri(),
                callback.getHeaders());
        return Failsafe.with(retryPolicy)
                .with(executor)
                .getStageAsync(
                        () -> httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                                .thenApply(validateResponse()));
    }

    private String getPodName(String environmentId) {
        return "pnc-ba-pod-" + environmentId;
    }

    private String getRouteName(String environmentId) {
        return "pnc-ba-route-" + environmentId;
    }

    private String getBuildAgentContextPath(String environmentId) {
        return "/pnc-ba-" + environmentId;
    }

    private String getServiceName(String environmentId) {
        return "pnc-ba-service-" + environmentId;
    }

    private String getSshServiceName(String environmentId) {
        return "pnc-ba-ssh-" + environmentId;
    }

    private void putMdcToResultMap(Map<String, String> result, Map<String, String> mdcMap, MDCHeaderKeys mdcHeaderKeys)
            throws DriverException {
        if (mdcMap == null) {
            throw new DriverException("Missing MDC map.");
        }
        if (mdcMap.get(mdcHeaderKeys.getMdcKey()) != null) {
            result.put(mdcHeaderKeys.getHeaderName(), mdcMap.get(mdcHeaderKeys.getMdcKey()));
        } else {
            throw new DriverException("Missing MDC value " + mdcHeaderKeys.getMdcKey());
        }
    }

    private List<Request.Header> getHeaders(String rawWebToken) {
        List<Request.Header> headers = new ArrayList<>();
        headers.add(new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON));
        if (rawWebToken != null) {
            headers.add(new Request.Header(HttpHeaders.AUTHORIZATION_STRING, "Bearer " + rawWebToken));
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
        String definition = StringSubstitutor.replace(resourceDefinition, properties, "%{", "}");

        if (logger.isTraceEnabled()) {
            logger.trace("Node definition: {}", secureLog(definition));
        }

        try {
            return yamlMapper.readValue(definition, clazz);
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
        putMdcToResultMap(result, mdcMap, MDCHeaderKeys.PROCESS_CONTEXT);
        putMdcToResultMap(result, mdcMap, MDCHeaderKeys.TMP);
        putMdcToResultMap(result, mdcMap, MDCHeaderKeys.EXP);
        putMdcToResultMap(result, mdcMap, MDCHeaderKeys.USER_ID);
        return result;
    }

    private boolean isHttpSuccess(int responseCode) {
        return responseCode >= 200 && responseCode < 300;
    }

    private Function<HttpResponse<String>, HttpResponse<String>> validateResponse() {
        return response -> {
            if (isHttpSuccess(response.statusCode())) {
                return response;
            } else {
                throw new FailedResponseException("Response status code: " + response.statusCode());
            }
        };
    }

    private List<String> getItemNames(List<? extends HasMetadata> items) {
        return items.stream().map(s -> s.getMetadata().getName()).collect(Collectors.toList());
    }

}
