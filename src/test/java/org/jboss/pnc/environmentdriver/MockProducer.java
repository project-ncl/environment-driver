package org.jboss.pnc.environmentdriver;

import java.util.Collections;
import java.util.HashMap;

import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

import io.fabric8.kubernetes.client.server.mock.KubernetesCrudDispatcher;
import io.fabric8.mockwebserver.Context;
import io.fabric8.openshift.client.OpenShiftClient;
import io.fabric8.openshift.client.server.mock.OpenShiftMockServer;
import okhttp3.mockwebserver.MockWebServer;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class MockProducer {

    OpenShiftMockServer openShiftMockServer;

    MockProducer() {
        openShiftMockServer = new OpenShiftMockServer(
                new Context(),
                new MockWebServer(),
                new HashMap<>(),
                new KubernetesCrudDispatcher(Collections.emptyList()),
                false);
        openShiftMockServer.init();
    }

    @Singleton
    @Produces
    public OpenShiftMockServer getOpenShiftServer() {
        return openShiftMockServer;
    }

    @Singleton
    @Produces
    public OpenShiftClient getOpenShiftClient() {
        return openShiftMockServer.createOpenShiftClient();
    }
}
