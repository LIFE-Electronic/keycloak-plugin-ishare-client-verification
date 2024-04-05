package com.life.keycloak.authentication.authenticators.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

class ISHARESatellitePartiesResponse implements Serializable {
    @JsonProperty("party_token")
    public String party_token;
}
