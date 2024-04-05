package com.life.keycloak.authentication.authenticators.client;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.BasicAuthHelper;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.Config;
import org.keycloak.common.util.Base64Url;
import org.keycloak.util.JsonSerialization;
import org.keycloak.common.util.PemException;
import org.keycloak.common.util.PemUtils;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.net.URL;
import java.io.FileInputStream;

/**
 * @author <a href="mailto:markus@life-electronic.nl">Markus Pfundstein</a>
 */
public class ISHAREAuthenticator extends AbstractClientAuthenticator {

    private static final Logger log = Logger.getLogger(ISHAREAuthenticator.class);

    public static final String PROVIDER_ID = "client-ishare";

    private String keycloakOperatorPartyId;
    private String iSHARESatellitePartyId;
    private String iSHARESatelliteBaseUrl;
    private X509Certificate iSHARE_CA;

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        log.debug("auth ISHARE");
        String client_id = null;
        String client_assertion = null;
        String client_assertion_type = null; 

        String authorizationHeader = context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
        boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters() : null;

        if (authorizationHeader != null) {
            String[] usernameSecret = BasicAuthHelper.RFC6749.parseHeader(authorizationHeader);
            if (usernameSecret != null) {
                client_id = usernameSecret[0];
            } else {
                // Don't send 401 if client_id parameter was sent in request. For example IE may automatically send "Authorization: Negotiate" in XHR requests even for public clients
                if (formData != null && !formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                    Response challengeResponse = Response.status(Response.Status.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + context.getRealm().getName() + "\"").build();
                    context.challenge(challengeResponse);
                    return;
                }
            }
        }

        if (formData != null) {
            // even if basic challenge response exist, we check if client id was explicitly set in the request as a form param,
            // so we can also support clients overriding flows and using challenges (e.g: basic) to authenticate their users
            if (formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                client_id = formData.getFirst(OAuth2Constants.CLIENT_ID);
            }

            if (formData.containsKey(OAuth2Constants.CLIENT_ASSERTION)) {
                client_assertion = formData.getFirst(OAuth2Constants.CLIENT_ASSERTION);
            }

            if (formData.containsKey(OAuth2Constants.CLIENT_ASSERTION_TYPE)) {
                client_assertion_type = formData.getFirst(OAuth2Constants.CLIENT_ASSERTION_TYPE);
            }
        }

        if (client_id == null) {
            client_id = context.getSession().getAttribute("client_id", String.class);
        }

        if (client_id == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Missing client_id parameter");
            context.challenge(challengeResponse);
            return;
        }

        if (client_assertion == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Missing client_assertion parameter");
            context.challenge(challengeResponse);
            return;
        }

        if (!validateClientAssertion(client_assertion)) {
            context.attempted();
            return;
        }
        
        context.getEvent().client(client_id);

        ClientModel client = context.getSession().clients().getClientByClientId(context.getRealm(), client_id);
        if (client == null) {
            context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
            return;
        }

        context.setClient(client);

        if (!client.isEnabled()) {
            context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
            return;
        }

        context.success();
        return;
    }

    private boolean validateClientAssertion(String client_assertion)
    {
        try {
            JWSInput jws = new JWSInput(client_assertion);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            
            // unfortunately no way to get x5c otherwise
            String encodedHeader = jws.getEncodedHeader();
            byte[] headerBytes = Base64Url.decode(encodedHeader);

            ISHAREJWSHeader header = JsonSerialization.readValue(headerBytes, ISHAREJWSHeader.class);

            String[] x5c = header.getX5C();
            if (x5c.length == 0) {
                log.error("x5c header value empty");
                return false;
            }
            log.debugf("--- certs ----");
            for (String s : x5c) {
                log.debugf("x5c: %s", s);
            }
            log.debug("----------------");

            // to do: make full chain
            List<X509Certificate> chain = new ArrayList<>();
            X509Certificate cert = PemUtils.decodeCertificate(x5c[0]);
            chain.add(cert);

            cert.verify(iSHARE_CA.getPublicKey());
            
            if (!token.isActive()) {
                log.error("token is not active anymore");
                // return false; // skip for debugging
            }
            
            if (!token.hasAudience(keycloakOperatorPartyId)) {
                log.error("invalid aud");
                return false;
            }
            // 0. validate jwt certificate
            
            // 1. Check if Keycloak operator is aud
           
            // if (keycloakOperatorPartyId not in aud) {
            //   throw
            // }

            // 2. validate sub at iSHARE satellite
            return true;
        } catch (Exception e) {
            log.errorf("Exception validating client_assertion: %s", e.toString());
        }        
        return false;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);

        keycloakOperatorPartyId = "NL.EORI.LIFEELEC4DMI";
        iSHARESatellitePartyId = "EU.EORI.NLDEXESDMISAT1";
        iSHARESatelliteBaseUrl = "https://satellite-mw.dev.dexes.eu";

        try {
            String u = "/home/markus/clients/dexes/ishare_certs/TESTiSHAREEUIssuingCertificationAuthorityG5-chain.pem";
            //String u = "/home/markus/clients/dexes/ishare_certs/Test_iSHARE_EU_Issuing_Certification_Authority_G5.pem";
            FileInputStream inStream = new FileInputStream(u);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            iSHARE_CA = (X509Certificate) cf.generateCertificate(inStream);
            
        } catch (java.io.FileNotFoundException e) {
            log.errorf("FileNotFoundException %s", e.toString());
        } catch (java.security.cert.CertificateException e) {
            log.errorf("CertificateException (iSHARE cert) %s", e.toString());
        }
    }
    
    @Override
    public String getDisplayType() {
        return "iSHARE";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "iSHARE Client Authenticator";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        //Map<String, Object> result = new HashMap<>();
        //result.put("ishare-satellite-url", "");
        //return result;
        return Collections.emptyMap();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        return Collections.emptySet();
    }
}
