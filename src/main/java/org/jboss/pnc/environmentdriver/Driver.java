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

import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_FAILED_KEY;
import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_FAILED_REASON_KEY;
import static org.jboss.pnc.environmentdriver.Constants.METRICS_POD_STARTED_SUCCESS_KEY;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.ws.rs.core.MediaType;

import io.quarkus.oidc.client.OidcClient;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.api.constants.HttpHeaders;
import org.jboss.pnc.api.constants.MDCHeaderKeys;
import org.jboss.pnc.api.constants.MDCKeys;
import org.jboss.pnc.api.dto.Request;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCompleteResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateRequest;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResponse;
import org.jboss.pnc.api.environmentdriver.dto.EnvironmentCreateResult;
import org.jboss.pnc.bifrost.upload.BifrostLogUploader;
import org.jboss.pnc.bifrost.upload.LogMetadata;
import org.jboss.pnc.bifrost.upload.TagOption;
import org.jboss.pnc.common.Random;
import org.jboss.pnc.common.Strings;
import org.jboss.pnc.common.log.MDCUtils;
import org.jboss.pnc.common.otel.OtelUtils;
import org.jboss.pnc.environmentdriver.clients.IndyService;
import org.jboss.pnc.environmentdriver.clients.IndyTokenRequestDTO;
import org.jboss.pnc.environmentdriver.clients.IndyTokenResponseDTO;
import org.jboss.pnc.environmentdriver.enums.PodErrorStatuses;
import org.jboss.pnc.environmentdriver.exceptions.BadResourcesRequestException;
import org.jboss.pnc.environmentdriver.exceptions.DriverException;
import org.jboss.pnc.environmentdriver.exceptions.FailedResponseException;
import org.jboss.pnc.environmentdriver.exceptions.QuotaExceededException;
import org.jboss.pnc.environmentdriver.exceptions.StoppingException;
import org.jboss.pnc.environmentdriver.exceptions.TemporarilyUnableToStartException;
import org.jboss.pnc.environmentdriver.exceptions.UnableToRequestResourcesException;
import org.jboss.pnc.environmentdriver.exceptions.UnableToStartException;
import org.jboss.pnc.environmentdriver.runtime.ApplicationLifecycle;
import org.jboss.pnc.pncmetrics.GaugeMetric;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.fabric8.kubernetes.api.model.Container;
import io.fabric8.kubernetes.api.model.ContainerStatus;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodList;
import io.fabric8.kubernetes.api.model.Quantity;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceList;
import io.fabric8.kubernetes.api.model.ServicePort;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.openshift.api.model.Route;
import io.fabric8.openshift.client.OpenShiftClient;
import io.opentelemetry.instrumentation.annotations.SpanAttribute;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@RequestScoped
public class Driver {

    private static final Logger logger = LoggerFactory.getLogger(Driver.class);

    public static final String ARCHIVAL_SERVICE_BUILD_CONFIG_ID = "BUILD_CONFIG_ID";

    public static final String ERROR_MESSAGE_INTRO = "\n\nAn error occurred while trying to create a build environment where to run the build. ";
    public static final String ERROR_MESSAGE_REGISTRY = "The builder pod failed to download the builder image "
            + "(this could be due to issues with the builder images registry, or a misconfiguration of the builder image name).";
    public static final String ERROR_MESSAGE_INVALID_IMAGE_NAME = "The builder pod failed to download the builder image "
            + "(the builder image has an invalid name).";
    public static final String ERROR_MESSAGE_INITIALIZATION = "The builder pod failed to start "
            + "(this could be due to misconfigured or bogus init scripts, or other unknown reasons).";
    public static final String ERROR_MESSAGE_TIMEOUT = " The maximum timeout has been reached. This could be due to an exhausted capacity of the underlying infrastructure "
            + "(there is no space available to create the new build environment).";
    public static final String ERROR_MESSAGE_TEMPLATE_PARSE = " The builder pod failed to start because an error occured while parsing either the pod or the service template.";
    public static final String ERROR_MESSAGE_EXCEEDED_QUOTA = " The maximum quota available for the build environments has been exceeded.";

    @Inject
    @UserLogger
    Logger userLogger;

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

    @Inject
    OidcClient oidcClient;

    @Inject
    BifrostLogUploader bifrostLogUploader;

    @RestClient
    IndyService indyService;

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
    @WithSpan()
    public CompletionStage<EnvironmentCreateResponse> create(
            @SpanAttribute(value = "environmentCreateRequest") EnvironmentCreateRequest environmentCreateRequest) {
        if (lifecycle.isShuttingDown()) {
            throw new StoppingException();
        }

        IndyTokenResponseDTO tokenResponseDTO = indyService.getAuthToken(
                new IndyTokenRequestDTO(environmentCreateRequest.getRepositoryBuildContentId()),
                "Bearer " + getFreshAccessToken());

        String environmentId = environmentCreateRequest.getEnvironmentLabel() + "-" + Random.randString(6);

        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);

        Map<String, String> podTemplateProperties = new HashMap<>();

        boolean proxyActive = configuration.getProxyServer().isPresent() && configuration.getProxyPort().isPresent();

        podTemplateProperties.put("image", environmentCreateRequest.getImageId());
        podTemplateProperties.put("firewallAllowedDestinations", configuration.getFirewallAllowedDestinations());
        podTemplateProperties
                .put("allowedHttpOutgoingDestinations", configuration.getAllowedHttpOutgoingDestinations().orElse(""));
        podTemplateProperties.put("isHttpActive", Boolean.toString(proxyActive).toLowerCase());
        podTemplateProperties.put("proxyServer", configuration.getProxyServer().orElse(""));
        podTemplateProperties.put("proxyPort", configuration.getProxyPort().orElse(""));
        podTemplateProperties.put("nonProxyHosts", configuration.getNonProxyHosts().orElse(""));

        podTemplateProperties.put("AProxDependencyUrl", environmentCreateRequest.getRepositoryDependencyUrl());
        podTemplateProperties.put("AProxDeployUrl", environmentCreateRequest.getRepositoryDeployUrl());

        podTemplateProperties.put("containerPort", configuration.getBuildAgentContainerPort());
        podTemplateProperties.put("buildContentId", environmentCreateRequest.getRepositoryBuildContentId());
        // TODO: use another style of token for the accessToken with Indy
        podTemplateProperties.put("accessToken", tokenResponseDTO.getToken());

        podTemplateProperties.put("workingDirectory", configuration.getWorkingDirectory());
        if (environmentCreateRequest.isSidecarArchiveEnabled()) {
            podTemplateProperties.put(ARCHIVAL_SERVICE_BUILD_CONFIG_ID, environmentCreateRequest.getBuildConfigId());
        } else {
            podTemplateProperties.put(ARCHIVAL_SERVICE_BUILD_CONFIG_ID, "");
        }

        try {
            podTemplateProperties.putAll(mdcToMap());
        } catch (DriverException e) {
            return CompletableFuture.failedFuture(e);
        }

        podTemplateProperties.put(
                "resourcesMemory",
                builderPodMemory(configuration.getBuilderPodMemory(), environmentCreateRequest.getPodMemoryOverride()));

        String buildAgentContextPath = getBuildAgentContextPath(environmentId);
        podTemplateProperties.put("environment-label", environmentCreateRequest.getEnvironmentLabel());
        podTemplateProperties.put("pod-name", podName);
        podTemplateProperties.put("service-name", serviceName);
        podTemplateProperties.put("buildAgentContextPath", buildAgentContextPath);

        String sshPassword;
        if (environmentCreateRequest.isAllowSshDebug()) {
            sshPassword = RandomStringUtils.randomAlphanumeric(10);
            podTemplateProperties.put("workerUserPassword", sshPassword);
        } else {
            sshPassword = "";
        }

        String podDefinition = configuration.getPodDefinition();

        CompletableFuture<Pod> podRequested = CompletableFuture.supplyAsync(() -> {
            Pod podCreationModel = createModelNode(podDefinition, podTemplateProperties, Pod.class);
            processPod(
                    podCreationModel,
                    environmentCreateRequest.isSidecarEnabled(),
                    environmentCreateRequest.isSidecarArchiveEnabled());
            return openShiftClient.pods().create(podCreationModel);
        }, executor);

        CompletableFuture<Service> serviceRequested = CompletableFuture.supplyAsync(() -> {
            Service serviceCreationModel = createModelNode(
                    configuration.getServiceDefinition(),
                    podTemplateProperties,
                    Service.class);
            return openShiftClient.services().create(serviceCreationModel);
        }, executor);

        // Handle the exceptions thrown by requests (e.g. KubernetesClientException for exceeded quota)
        CompletableFuture<Void> requestFailure = new CompletableFuture<>();
        podRequested.exceptionally(ex -> {
            requestFailure.completeExceptionally(ex);
            return null;
        });
        serviceRequested.exceptionally(ex -> {
            requestFailure.completeExceptionally(ex);
            return null;
        });

        // Do not wait for both podRequested and serviceRequested completion, one exception
        // of them is enough to stop waiting for the other
        CompletableFuture<Void> podAndServiceRequested = CompletableFuture.allOf(podRequested, serviceRequested);
        Map<String, String> mdc = MDCUtils.getHeadersFromMDC();
        return CompletableFuture.anyOf(requestFailure, podAndServiceRequested).thenApplyAsync((nul) -> {
            startMonitor(
                    serviceName,
                    buildAgentContextPath,
                    podName,
                    environmentCreateRequest.getCompletionCallback(),
                    sshPassword,
                    mdc);
            return new EnvironmentCreateResponse(environmentId, getCancelRequest(environmentId));
        }, executor).exceptionally(throwable -> {

            Throwable rootCause = getRootCause(throwable);
            logger.error("Exception thrown with message: {}", throwable, rootCause);

            gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_KEY));

            if (rootCause != null && rootCause instanceof MismatchedInputException) {
                userLogger.error(ERROR_MESSAGE_INTRO + ERROR_MESSAGE_TEMPLATE_PARSE);
                throw new BadResourcesRequestException(ERROR_MESSAGE_INTRO + ERROR_MESSAGE_TEMPLATE_PARSE, rootCause);

            } else if (rootCause != null && rootCause instanceof KubernetesClientException
                    && rootCause.getMessage().contains("exceeded quota")) {

                userLogger.error(ERROR_MESSAGE_INTRO + ERROR_MESSAGE_EXCEEDED_QUOTA);
                throw new QuotaExceededException(ERROR_MESSAGE_INTRO + ERROR_MESSAGE_EXCEEDED_QUOTA, rootCause);

            }
            userLogger.error(rootCause != null ? rootCause.getMessage() : throwable.getMessage());
            throw new UnableToRequestResourcesException(
                    rootCause != null ? rootCause.getMessage() : throwable.getMessage());
        });
    }

    private void processPod(Pod pod, boolean sidecarEnabled, boolean sidecarArchiveEnabled) {
        if (!sidecarEnabled) {
            List<Container> containers = pod.getSpec().getContainers();
            Optional<Container> sidecarContainer = containers.stream()
                    .filter(c -> "sidecar".equals(c.getName()))
                    .findFirst();
            if (!sidecarContainer.isEmpty()) {
                containers.remove(sidecarContainer.get());
            }
        }
        if (!sidecarArchiveEnabled) {
            List<Container> initContainers = pod.getSpec().getInitContainers();
            Optional<Container> sidecarInitContainer = initContainers.stream()
                    .filter(c -> "sidecar-init".equals(c.getName()))
                    .findFirst();
            if (!sidecarInitContainer.isEmpty()) {
                initContainers.remove(sidecarInitContainer.get());
            }
        }
    }

    private Request getCancelRequest(String environmentId) {
        return Request.builder()
                .method(Request.Method.PUT)
                .uri(
                        URI.create(
                                Strings.stripEndingSlash(configuration.getThisServiceBaseUrl()) + "/cancel/"
                                        + environmentId))
                .headers(getHeaders())
                .build();
    }

    @WithSpan()
    public CompletionStage<EnvironmentCompleteResponse> enableDebug(
            @SpanAttribute(value = "environmentId") String environmentId) {
        Map<String, String> serviceTemplateProperties = new HashMap<>();
        serviceTemplateProperties.put("pod-name", getPodName(environmentId));
        serviceTemplateProperties.put("ssh-service-name", getSshServiceName(environmentId));

        Map<String, String> routeTemplateProperties = new HashMap<>();
        routeTemplateProperties.put("route-name", getRouteName(environmentId));
        routeTemplateProperties.put("route-path", getBuildAgentContextPath(environmentId));
        routeTemplateProperties.put("service-name", getServiceName(environmentId));
        routeTemplateProperties.put("build-agent-host", configuration.getBuildAgentHost());

        // Enable ssh forwarding and complete with the port to which ssh is forwarded
        return CompletableFuture.supplyAsync(() -> {
            Service serviceCreationModel = createModelNode(
                    configuration.getSshServiceDefinition(),
                    serviceTemplateProperties,
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
                    routeTemplateProperties,
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
                .withBackoff(
                        configuration.getSshPingRetryDelayMsec(),
                        configuration.getSshPingRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS) // don't wait too long, the response is waiting
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
    @WithSpan()
    public void destroy(@SpanAttribute(value = "environmentId") String environmentId) {
        String podName = getPodName(environmentId);
        String serviceName = getServiceName(environmentId);
        activeMonitors.cancel(podName);

        // delete service
        RetryPolicy<String> serviceRetryPolicy = getDestroyRetryPolicy(serviceName);
        Failsafe.with(serviceRetryPolicy).with(executor).runAsync(() -> {
            Service service = openShiftClient.services().withName(serviceName).get();
            if (service != null) {
                openShiftClient.services().delete(service);
                logger.info("Service {} deleted.", serviceName);
            } else {
                logger.warn("Service {} does not exists.", serviceName);
            }
        });
        // delete pod
        RetryPolicy<String> podRetryPolicy = getDestroyRetryPolicy(podName);
        Failsafe.with(podRetryPolicy).with(executor).runAsync(() -> {
            Pod pod = openShiftClient.pods().withName(podName).get();
            if (pod != null) {
                openShiftClient.pods().delete(pod);
                logger.info("Pod {} deleted.", podName);
            } else {
                logger.warn("Pod {} does not exists.", podName);
            }
        });
    }

    private RetryPolicy<String> getDestroyRetryPolicy(String resourceName) {
        return new RetryPolicy<String>().withMaxDuration(Duration.ofSeconds(configuration.getDestroyRetryDuration()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(
                        configuration.getDestroyRetryDelayMsec(),
                        configuration.getDestroyRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS)
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
    @WithSpan()
    public void destroyAll(@SpanAttribute(value = "environmentLabel") String environmentLabel) {
        // delete service
        RetryPolicy<String> servicesRetryPolicy = getDestroyRetryPolicy("services-of-" + environmentLabel);
        Failsafe.with(servicesRetryPolicy).with(executor).runAsync(() -> {
            ServiceList serviceList = openShiftClient.services().withLabel("environment", environmentLabel).list();
            if (serviceList != null) {
                openShiftClient.services().delete(serviceList.getItems());
                logger.info("Services {} deleted.", getItemNames(serviceList.getItems()));
            } else {
                logger.warn("No services found by label {}.", environmentLabel);
            }
        });
        // delete pod
        RetryPolicy<String> podsRetryPolicy = getDestroyRetryPolicy("pods-of-" + environmentLabel);
        Failsafe.with(podsRetryPolicy).with(executor).runAsync(() -> {
            PodList podList = openShiftClient.pods().withLabel("environment", environmentLabel).list();
            if (podList != null) {
                openShiftClient.pods().delete(podList.getItems());
                logger.info("Pods {} deleted.", getItemNames(podList.getItems()));
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
            String sshPassword,
            Map<String, String> mdc) {
        lifecycle.addActiveOperation();
        CompletableFuture<URI> serviceRunning = isServiceRunning(serviceName);
        activeMonitors.add(podName, serviceRunning);

        CompletableFuture<Void> podRunning = isPodRunning(podName);
        activeMonitors.add(podName, podRunning);

        // Do not wait for both podRunning and serviceRunning completion, one exception
        // of them is enough to stop
        // waiting for the other
        CompletableFuture<Void> failure = new CompletableFuture<>();
        podRunning.exceptionally(ex -> {
            failure.completeExceptionally(ex);
            return null;
        });
        serviceRunning.exceptionally(ex -> {
            failure.completeExceptionally(ex);
            return null;
        });

        CompletableFuture.anyOf(failure, CompletableFuture.allOf(podRunning, serviceRunning))
                .thenComposeAsync((nul) -> {
                    URI serviceBaseUri = serviceRunning.join(); // future already completed (allOff)
                    String serviceUriWithContext = serviceBaseUri + buildAgentContextPath;
                    CompletableFuture<HttpResponse<String>> pingFuture = pingBuildAgent(serviceUriWithContext);
                    activeMonitors.add(podName, pingFuture);
                    return pingFuture.thenApply((ignoreResponse) -> URI.create(serviceUriWithContext));
                })
                .handleAsync((serviceUriWithContext, throwable) -> {
                    logger.info("Completing monitor for pod: {}", podName);
                    activeMonitors.remove(podName);
                    CompletableFuture<HttpResponse<String>> callback;
                    if (throwable != null) {
                        logger.info("Received throwable: {}", throwable);
                        if (throwable instanceof CancellationException
                                || throwable.getCause() instanceof CancellationException) {

                            callback = callback(completionCallback, EnvironmentCreateResult.cancelled(), mdc);

                        } else if (throwable instanceof TemporarilyUnableToStartException
                                || throwable.getCause() instanceof TemporarilyUnableToStartException) {

                            callback = callback(
                                    completionCallback,
                                    EnvironmentCreateResult.systemError(throwable),
                                    mdc);
                            gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_KEY));

                        } else {

                            callback = callback(completionCallback, EnvironmentCreateResult.failed(throwable), mdc);
                            gaugeMetric.ifPresent(g -> g.incrementMetric(METRICS_POD_STARTED_FAILED_KEY));
                        }
                    } else {
                        EnvironmentCreateResult environmentCreateResult = EnvironmentCreateResult
                                .success(serviceUriWithContext, configuration.getWorkingDirectory(), sshPassword);
                        callback = callback(completionCallback, environmentCreateResult, mdc);
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

    private String getPodRequestedVsAvailableResourcesInfo(String podName) {

        String msg = "\n";
        try {
            double memoryUsedByPod = calculateResourceUsedByPod(podName, "memory");
            double cpuUsedByPod = calculateResourceUsedByPod(podName, "cpu");

            msg += String
                    .format("Pod %s requested resources: %.2fGB %.1fcpu; ", podName, memoryUsedByPod, cpuUsedByPod);
        } catch (KubernetesClientException kEx) {
            logger.warn("Cannot calculate Pod {} requested resources", podName, kEx);
        } catch (RuntimeException rEx) {
            logger.warn("Cannot convert Pod {} requested resources", podName, rEx);
        }

        try {
            double availableMemory = calculateAvailableResource("memory");
            double availableCpu = calculateAvailableResource("cpu");

            msg += String.format("Available resources: %.2fGB %.1fcpu", availableMemory, availableCpu);
        } catch (KubernetesClientException kEx) {
            logger.warn("Cannot calculate available resources in the namespace of Pod {}", podName, kEx);
        } catch (RuntimeException rEx) {
            logger.warn("Cannot convert available resources in the namespace of Pod {}", podName, rEx);
        } catch (Exception ex) {
            logger.warn("Error while getting available resources in the namespace of Pod {}", podName, ex);
        }

        return msg;
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
                .findFirst() // Only consider the first quota,
                             // we generally only use one!
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
                .withBackoff(
                        configuration.getPodRunningRetryDelayMsec(),
                        configuration.getPodRunningRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS)
                .abortOn(UnableToStartException.class, TemporarilyUnableToStartException.class)
                .onSuccess(ctx -> userLogger.info("Pod {} is running.", podName))
                .onRetry(
                        // Received the DriverException
                        ctx -> userLogger.warn(
                                "Running pod {} check #{}; last checked status: [{}].",
                                podName,
                                ctx.getAttemptCount(),
                                ctx.getLastFailure() != null ? ctx.getLastFailure().getMessage() : ""))
                .onRetriesExceeded(ctx -> {
                    String errMsg = String.format(
                            "Unable to start pod %s. %s",
                            podName,
                            (ctx.getFailure() != null ? ctx.getFailure().getMessage() : ""));
                    errMsg += ERROR_MESSAGE_INTRO + ERROR_MESSAGE_TIMEOUT
                            + getPodRequestedVsAvailableResourcesInfo(podName);

                    userLogger.warn(errMsg);
                    throw new UnableToStartException(errMsg);
                })
                .onFailure(
                        ctx -> userLogger.error(
                                "Unable to start pod {}. {}",
                                podName,
                                (ctx.getFailure() != null ? ctx.getFailure().getMessage() : "")))
                .onAbort(
                        // Received the UnableToStartException
                        e -> logger.info(
                                "IsPodRunning for pod {} was aborted. {}",
                                podName,
                                (e.getFailure() != null ? e.getFailure().getMessage() : "")));

        return Failsafe.with(retryPolicy).with(executor).runAsync(() -> {
            Pod pod = openShiftClient.pods().withName(podName).get();
            String podStatus = pod.getStatus().getPhase();
            // Get all the termination or waiting reasons for the containers inside the Pod
            Set<String> containerStatuses = new HashSet<>();
            if (pod.getStatus().getInitContainerStatuses() != null) {
                for (ContainerStatus containerStatus : pod.getStatus().getInitContainerStatuses()) {
                    if (containerStatus.getState() != null) {
                        if (containerStatus.getState().getTerminated() != null) {
                            containerStatuses.add(containerStatus.getState().getTerminated().getReason());
                        }
                        if (containerStatus.getState().getWaiting() != null) {
                            containerStatuses.add(containerStatus.getState().getWaiting().getReason());
                        }
                    }
                }
            }
            if (pod.getStatus().getContainerStatuses() != null) {
                for (ContainerStatus containerStatus : pod.getStatus().getContainerStatuses()) {
                    if (containerStatus.getState() != null) {
                        if (containerStatus.getState().getTerminated() != null) {
                            containerStatuses.add(containerStatus.getState().getTerminated().getReason());
                        }
                        if (containerStatus.getState().getWaiting() != null) {
                            containerStatuses.add(containerStatus.getState().getWaiting().getReason());
                        }
                    }
                }
            }
            logger.info("Pod {} status: {} containersStatusesReasons: {}", podName, podStatus, containerStatuses);

            // If the pod final status OR any status of all the containers in the pod are among the failed statuses,
            // abort isPodRunning
            Optional<PodErrorStatuses> failedPodStatus = PodErrorStatuses.getIfPresent(podStatus);
            Optional<PodErrorStatuses> failedContainerStatus = PodErrorStatuses.getIfPresent(containerStatuses);

            if (failedPodStatus.isPresent() || failedContainerStatus.isPresent()) {
                // The status was among the failed statuses
                PodErrorStatuses detectedPodErrorStatus = failedPodStatus.isPresent() ? failedPodStatus.get()
                        : failedContainerStatus.get();

                gaugeMetric.ifPresent(
                        g -> g.incrementMetric(
                                METRICS_POD_STARTED_FAILED_REASON_KEY + "." + detectedPodErrorStatus.getStatus()));

                if (!detectedPodErrorStatus.isRetryable()) {
                    throw new UnableToStartException(
                            "Pod failed with status: " + detectedPodErrorStatus.getStatus()
                                    + detectedPodErrorStatus.getCustomErrMsg());
                } else {
                    throw new TemporarilyUnableToStartException(
                            "Pod failed with status: " + detectedPodErrorStatus.getStatus()
                                    + detectedPodErrorStatus.getCustomErrMsg());
                }
            }

            boolean isRunning = "Running".equals(podStatus);
            if (!isRunning) {
                throw new DriverException("Pod " + podName + " is not running.");
            }
        });
    }

    private CompletableFuture<URI> isServiceRunning(String serviceName) {
        RetryPolicy<Object> retryPolicy = new RetryPolicy<>()
                .withMaxDuration(Duration.ofSeconds(configuration.getServiceRunningWaitFor()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(
                        configuration.getServiceRunningRetryDelayMsec(),
                        configuration.getServiceRunningRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS)
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
                userLogger.info("Service {} is up with ip {}.", serviceName, clusterIP);
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
                .withBackoff(
                        configuration.getBuildAgentRunningRetryDelayMsec(),
                        configuration.getBuildAgentRunningRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS)
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
            EnvironmentCreateResult environmentCreateResult,
            Map<String, String> mdc) {

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

        // Add the service account's access token.
        builder.header(javax.ws.rs.core.HttpHeaders.AUTHORIZATION, "Bearer " + getFreshAccessToken());
        HttpRequest request = builder.build();

        RetryPolicy<HttpResponse<String>> retryPolicy = new RetryPolicy<HttpResponse<String>>()
                .withMaxDuration(Duration.ofSeconds(configuration.getCallbackRetryDuration()))
                .withMaxRetries(Integer.MAX_VALUE) // retry until maxDuration is reached
                .withBackoff(
                        configuration.getCallbackRetryDelayMsec(),
                        configuration.getCallbackRetryMaxDelayMsec(),
                        ChronoUnit.MILLIS)
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
        logger.info(
                "About to callback: {} {}. With headers: {}.",
                callback.getMethod(),
                callback.getUri(),
                callback.getHeaders());

        try {
            uploadResultToBifrost(environmentCreateResult, mdc);
        } catch (Exception e) {
            // I guess we're ok if we don't have those logs?
            logger.warn("Could not send log to Bifrost", e);
        }

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
            result.put(mdcHeaderKeys.getMdcKey(), mdcMap.get(mdcHeaderKeys.getMdcKey()));
        } else {
            throw new DriverException("Missing MDC value " + mdcHeaderKeys.getMdcKey());
        }
    }

    private void putOtelMdcToResultMap(Map<String, String> result, Map<String, String> mdcMap) throws DriverException {
        if (mdcMap == null) {
            throw new DriverException("Missing MDC map.");
        }

        String trace = mdcMap.get(MDCKeys.TRACE_ID_KEY);
        String span = mdcMap.get(MDCKeys.SPAN_ID_KEY);
        String traceFlags = mdcMap.get(MDCKeys.TRACE_FLAGS_KEY);

        if (!Strings.isEmpty(trace)) {
            result.put(MDCKeys.TRACE_ID_KEY, trace);
        }
        if (!Strings.isEmpty(span)) {
            result.put(MDCKeys.SPAN_ID_KEY, span);
        }

        Map<String, String> traceparentHeader = OtelUtils.createTraceParentHeader(trace, span, traceFlags);
        String traceparent = traceparentHeader.get(MDCHeaderKeys.TRACEPARENT.getHeaderName());
        if (!Strings.isEmpty(traceparent)) {
            result.put(MDCHeaderKeys.TRACEPARENT.getMdcKey(), traceparent);
        }
    }

    private List<Request.Header> getHeaders() {
        List<Request.Header> headers = new ArrayList<>();
        headers.add(new Request.Header(HttpHeaders.CONTENT_TYPE_STRING, MediaType.APPLICATION_JSON));

        MDCUtils.getHeadersFromMDC().forEach((headerName, headerValue) -> {
            headers.add(new Request.Header(headerName, headerValue));
        });
        return headers;
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

        putOtelMdcToResultMap(result, mdcMap);
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

    private static Throwable getRootCause(Throwable throwable) {
        final List<Throwable> list = new ArrayList<>();
        while (throwable != null && !list.contains(throwable)) {
            list.add(throwable);
            throwable = throwable.getCause();
        }
        return list.isEmpty() ? null : list.get(list.size() - 1);
    }

    /**
     * Upload the final log to bifrost
     *
     * We need to capture the mdc values here since this method is called from a completablefuture where the MDC values
     * are lost from the original caller. So we need to capture MDC values from the original caller and pass it around
     *
     * @param environmentCreateResult
     * @param mdc
     */
    private void uploadResultToBifrost(EnvironmentCreateResult environmentCreateResult, Map<String, String> mdc) {
        LogMetadata logMetadata = LogMetadata.builder()
                .tag(TagOption.BUILD_LOG)
                .loggerName(userLogger.getName())
                .endTime(OffsetDateTime.now())
                .headers(mdc)
                .build();

        logger.info("Uploading result to Bifrost");
        if (environmentCreateResult.getStatus().isSuccess()) {
            bifrostLogUploader.uploadString("", logMetadata);
        } else {
            String message = environmentCreateResult.getMessage();
            bifrostLogUploader.uploadString(message, logMetadata);
        }
    }

    /**
     * Get a fresh access token for the service account. This is done because we want to get a super-new token to be
     * used since we're not entirely sure when the http request will be done inside the completablefuture.
     *
     * @return fresh access token
     */
    private String getFreshAccessToken() {
        return oidcClient.getTokens().await().indefinitely().getAccessToken();
    }
}
