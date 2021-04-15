package org.jboss.pnc.environmentdriver;

import java.net.http.HttpClient;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;

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

    private HttpClient httpClient;

    @PostConstruct
    void init() throws NoSuchAlgorithmException {
        httpClient = java.net.http.HttpClient.newBuilder()
                .sslContext(SSLContext.getDefault())
                .executor(executor)
                .connectTimeout(Duration.ofSeconds(configuration.getHttpClientConnectTimeout()))
                .build();
    }

    @Produces
    @ApplicationScoped
    public HttpClient getHttpClient() {
        return httpClient;
    }
}
