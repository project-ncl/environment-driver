package org.jboss.pnc.environmentdriver.pncclientauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.Tokens;

/**
 * NOTE: code duplicated from the quarkus-pnc-client-auth extension
 * It is duplicated because the extension is Quarkus 3 only, and we're still using
 * Quarkus 2 for this project. Once we migrate to Quarkus 3, this can be replaced
 * by the extension
 *
 * Easily select the client authentication type (LDAP, OIDC [default]) that will be used to send authenticated requests
 * to other applications.
 *
 * If OIDC is used, the user will have to specify the quarkus-oidc-client fields. If LDAP is used, the uer will have to
 * specify the client_auth.ldap_credentials.path
 */
@ApplicationScoped
public class PNCClientAuthImpl implements PNCClientAuth {

    @Inject
    OidcClient oidcClient;

    /**
     * Used to get cached OIDC token value, rather than getting a fresh one all the time
     */
    @Inject
    Tokens tokens;

    @ConfigProperty(name = "pnc_client_auth.type", defaultValue = "OIDC")
    ClientAuthType clientAuthType;

    /**
     * The path must be a file with format: username:password
     */
    @ConfigProperty(name = "pnc_client_auth.ldap_credentials.path")
    Optional<String> ldapCredentialsPath;

    @Override
    public String getAuthToken() {
        try {
            return switch (clientAuthType) {
                case OIDC -> oidcClient.getTokens().await().atMost(Duration.ofMinutes(5)).getAccessToken();
                case LDAP -> Base64.getEncoder()
                        .encodeToString(getLDAPCredentialsFileContent().getBytes(StandardCharsets.UTF_8));
            };
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getHttpAuthorizationHeaderValue() {
        return switch (clientAuthType) {
            case OIDC -> "Bearer " + getAuthToken();
            case LDAP -> "Basic " + getAuthToken();
        };
    }

    @Override
    public String getHttpAuthorizationHeaderValueWithCachedToken() {
        return switch (clientAuthType) {
            case OIDC -> "Bearer " + tokens.getAccessToken();
            case LDAP -> "Basic " + getAuthToken();
        };
    }

    @Override
    public LDAPCredentials getLDAPCredentials() throws IOException {
        String content = getLDAPCredentialsFileContent();
        String[] valuesSeparated = content.split(":");
        if (valuesSeparated.length == 2) {
            return new LDAPCredentials(valuesSeparated[0], valuesSeparated[1]);
        } else {
            throw new RuntimeException("LDAP Credentials file is not formatted properly <username>:<password>");
        }
    }

    private String getLDAPCredentialsFileContent() throws IOException {

        if (ldapCredentialsPath.isEmpty()) {
            throw new RuntimeException("client_auth.ldap_credentials.path is empty!");
        }

        return Files.readString(Path.of(ldapCredentialsPath.get())).strip();
    }
}
