package com.life.keycloak.authentication.authenticators.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;


@JsonIgnoreProperties(ignoreUnknown = true)
class Adherence implements Serializable
{
    @JsonProperty("status")
    public String status;
}

@JsonIgnoreProperties(ignoreUnknown = true)
class ISHAREPartyInfo implements Serializable {
    @JsonProperty("party_id")
    public String party_id;

    @JsonProperty("registrar_id")
    public String registrar_id;

    @JsonProperty("adherence")
    public Adherence adherence;
}
