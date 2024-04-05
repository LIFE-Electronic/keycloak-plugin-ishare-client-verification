package com.life.keycloak.authentication.authenticators.client;

import org.keycloak.jose.jws.JWSHeader;
import com.fasterxml.jackson.annotation.JsonProperty;

class ISHAREJWSHeader extends JWSHeader
{
    @JsonProperty("x5c")
    private String[] x5c;

    public String[] getX5C() {
        return x5c;
    }
}

