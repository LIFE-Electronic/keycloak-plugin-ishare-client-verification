package com.life.keycloak.authentication.authenticators.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

class ISHARESatelliteResponse implements Serializable {
    @JsonProperty("status")
    public String status;

    @JsonProperty("message")
    public String message;

    @JsonProperty("access_token")
    public String access_token;

    @JsonProperty("token_type")
    public String token_type;

    @JsonProperty("expires_in")
    public int expires_in;

    public ISHARESatelliteResponse() {}
}
