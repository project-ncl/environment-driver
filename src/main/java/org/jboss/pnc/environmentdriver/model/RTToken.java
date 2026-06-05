package org.jboss.pnc.environmentdriver.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

@Builder
@Jacksonized
@JsonIgnoreProperties(ignoreUnknown = true)
public record RTToken(@JsonProperty("token_id") String tokenId,
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("reference_token") String referenceToken,
        @JsonProperty("expires_in") String expiresIn,
        @JsonProperty("scope") String scope,
        @JsonProperty("token_type") String tokenType) {
}
