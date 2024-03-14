package org.jboss.pnc.environmentdriver;

import io.quarkus.oidc.client.OidcClient;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.pnc.bifrost.upload.BifrostLogUploader;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.net.URI;
import java.time.Duration;

@ApplicationScoped
public class BifrostLogUploaderProducer {

    @ConfigProperty(name = "bifrost-uploader.api-url")
    private URI bifrostUrl;
    @ConfigProperty(name = "bifrost-uploader.maxRetries", defaultValue = "6")
    private int maxRetries;
    @ConfigProperty(name = "bifrost-uploader.retryDelay", defaultValue = "10")
    private int retryDelay;

    @Inject
    OidcClient oidcClient;

    private String getFreshAccessToken() {
        return oidcClient.getTokens().await().atMost(Duration.ofSeconds(10)).getAccessToken();
    }

    @Produces
    @ApplicationScoped
    public BifrostLogUploader produce() {
        return new BifrostLogUploader(bifrostUrl, maxRetries, retryDelay, this::getFreshAccessToken);
    }
}
