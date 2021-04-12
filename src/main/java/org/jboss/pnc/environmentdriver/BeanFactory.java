package org.jboss.pnc.environmentdriver;

import java.net.http.HttpClient;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;

import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.openshift.client.DefaultOpenShiftClient;
import io.fabric8.openshift.client.OpenShiftClient;
import org.eclipse.microprofile.context.ManagedExecutor;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@ApplicationScoped
public class BeanFactory {

    @Inject
    Configuration configuration;

    @Inject
    ManagedExecutor executor;

    private OpenShiftClient openShiftClient;

    private HttpClient httpClient;

    @PostConstruct
    void init() throws NoSuchAlgorithmException {
        Config config = new ConfigBuilder().withNamespace(configuration.getOpenshiftNamespace())
                .withMasterUrl(configuration.getOpenshiftApiUrl())
                .withOauthToken(configuration.getOpenshiftApiToken())
                .withConnectionTimeout(configuration.getOpenshiftClientConnectionTimeout())
                .withRequestTimeout(configuration.getOpenshiftClientRequestTimeout())
                .build();
        openShiftClient = new DefaultOpenShiftClient(config);

        httpClient = java.net.http.HttpClient.newBuilder()
                .sslContext(SSLContext.getDefault())
                .executor(executor)
                .connectTimeout(Duration.ofSeconds(configuration.getHttpClientConnectTimeout()))
                .build();
    }

    @Produces
    @ApplicationScoped
    public OpenShiftClient getOpenShiftClient() {
        return openShiftClient;
    }

    @Produces
    @ApplicationScoped
    public HttpClient getHttpClient() {
        return httpClient;
    }
}
