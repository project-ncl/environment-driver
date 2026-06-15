package org.jboss.pnc.environmentdriver.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

@Builder
@Jacksonized
public record RTRevokeTokenRequest(
        /**
         * The value can be either JWT or ReferenceToken
         */
        @JsonProperty("token") String token) {
}
