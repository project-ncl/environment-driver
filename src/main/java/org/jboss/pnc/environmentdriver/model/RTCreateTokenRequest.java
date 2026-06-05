package org.jboss.pnc.environmentdriver.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

@Builder
@Jacksonized
public record RTCreateTokenRequest(@JsonProperty("username") String username,
                                   @JsonProperty("scope") String scope,
                                   @JsonProperty("expires_in") Integer expiresIn) {
}
