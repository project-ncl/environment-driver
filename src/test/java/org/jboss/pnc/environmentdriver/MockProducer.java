package org.jboss.pnc.environmentdriver;

import java.util.Collections;
import java.util.HashMap;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.fabric8.kubernetes.client.server.mock.KubernetesCrudDispatcher;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import io.fabric8.mockwebserver.Context;
import io.fabric8.mockwebserver.MockWebServer;
import io.fabric8.openshift.client.OpenShiftClient;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class MockProducer {

    KubernetesMockServer mockServer;

    MockProducer() {
        mockServer = new KubernetesMockServer(
                new Context(),
                new MockWebServer(),
                new HashMap<>(),
                new KubernetesCrudDispatcher(Collections.emptyList()),
                false);
        mockServer.init();
    }

    @Singleton
    @Produces
    public OpenShiftClient getOpenShiftClient() {
        return mockServer.createClient().adapt(OpenShiftClient.class);
    }
}
