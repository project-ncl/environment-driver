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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@ApplicationScoped
public class BeanFactory {

    public static final Logger userLogger = LoggerFactory.getLogger("org.jboss.pnc._userlog_.envdriver");

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

    @UserLogger
    @Produces
    @ApplicationScoped
    public Logger getUserLogger() {
        return userLogger;
    }

    @Produces
    @ApplicationScoped
    public HttpClient getHttpClient() {
        return httpClient;
    }
}
