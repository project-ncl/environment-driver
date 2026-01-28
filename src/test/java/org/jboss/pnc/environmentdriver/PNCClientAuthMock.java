package org.jboss.pnc.environmentdriver;

import org.jboss.pnc.quarkus.client.auth.runtime.PNCClientAuth;

import io.quarkus.test.Mock;

@Mock
public class PNCClientAuthMock implements PNCClientAuth {
    @Override
    public String getAuthToken() {
        return "1234";
    }

    @Override
    public String getHttpAuthorizationHeaderValue() {
        return "Bearer 1234";
    }
}
