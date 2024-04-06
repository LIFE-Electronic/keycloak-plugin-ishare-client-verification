package com.life.keycloak.authentication.authenticators.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
class ISHAREAuthenticatorConfig implements Serializable {
    @JsonProperty(value="operator-id", required=true)
    public String operatorId;

    @JsonProperty(value="operator-cert-file", required=true)
    public String certFile;

    @JsonProperty(value="operator-pk-file", required=true)
    public String pkFile;

    @JsonProperty(value="satellite-id", required=true)
    public String satelliteId;

    @JsonProperty(value="satellite-url", required=true)
    public String satelliteUrl;

    @JsonProperty(value="ishare-ca-file", required=true)
    public String ishareCaFile;
}
