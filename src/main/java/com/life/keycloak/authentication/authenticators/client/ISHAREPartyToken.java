package com.life.keycloak.authentication.authenticators.client;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.keycloak.representations.JsonWebToken;

class ISHAREPartyToken extends JsonWebToken {
    @JsonProperty("party_info")
    public ISHAREPartyInfo party_info;
}


