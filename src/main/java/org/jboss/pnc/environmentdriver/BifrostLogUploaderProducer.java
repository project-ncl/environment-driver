package org.jboss.pnc.environmentdriver;

import java.net.URI;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.pnc.bifrost.upload.BifrostLogUploader;
import org.jboss.pnc.environmentdriver.pncclientauth.PNCClientAuth;

@ApplicationScoped
public class BifrostLogUploaderProducer {

    @ConfigProperty(name = "bifrost-uploader.api-url")
    private URI bifrostUrl;
    @ConfigProperty(name = "bifrost-uploader.maxRetries", defaultValue = "6")
    private int maxRetries;
    @ConfigProperty(name = "bifrost-uploader.retryDelay", defaultValue = "10")
    private int retryDelay;

    @Inject
    PNCClientAuth pncClientAuth;

    @Produces
    @ApplicationScoped
    public BifrostLogUploader produce() {
        return new BifrostLogUploader(
                bifrostUrl,
                pncClientAuth::getHttpAuthorizationHeaderValue,
                maxRetries,
                retryDelay);
    }
}
