package org.jboss.pnc.environmentdriver.dto;

import java.net.URI;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@Getter
@Jacksonized
@Builder(builderClassName = "Builder")
@JsonIgnoreProperties(ignoreUnknown = true)
public class EnvironmentCreationCompleted {

    private final URI environmentBaseUri;
    private final String workingDirectory;
    private final String sshPassword;
    private final Status status;
    private final String message;

    public static EnvironmentCreationCompleted cancelled() {
        return EnvironmentCreationCompleted.builder().status(Status.CANCELLED).build();
    }

    public static EnvironmentCreationCompleted failed(Throwable throwable) {
        return EnvironmentCreationCompleted.builder().status(Status.FAILED).message(throwable.getMessage()).build();
    }

    public static EnvironmentCreationCompleted success(
            URI environmentBaseUri,
            String workingDirectory,
            String sshPassword) {
        return EnvironmentCreationCompleted.builder()
                .status(Status.SUCCESS)
                .environmentBaseUri(environmentBaseUri)
                .workingDirectory(workingDirectory)
                .sshPassword(sshPassword)
                .build();
    }

    public enum Status {
        CANCELLED, FAILED, SUCCESS
    }
}
