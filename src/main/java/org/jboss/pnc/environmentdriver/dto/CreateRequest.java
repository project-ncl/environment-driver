package org.jboss.pnc.environmentdriver.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;
import org.jboss.pnc.api.dto.Request;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@Getter
@AllArgsConstructor
@Jacksonized
@Builder(builderClassName = "Builder")
@JsonIgnoreProperties(ignoreUnknown = true)
public class CreateRequest {

    private String environmentLabel;

    private Request completionCallback;

    private String imageId;

    private String repositoryDependencyUrl;

    private String repositoryDeployUrl;

    private String repositoryBuildContentId;

    private String podMemoryOverride;

    private boolean allowSshDebug;
}
