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
import org.keycloak.provider.ProviderConfigurationBuilder;


import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import io.jsonwebtoken.*;

import org.jboss.logging.Logger;

import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.*;
import java.net.URL;
import java.net.URI;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.io.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;



/**
 * @author <a href="mailto:markus@life-electronic.nl">Markus Pfundstein</a>
 */
public class ISHAREAuthenticator extends AbstractClientAuthenticator {

    private static final Logger log = Logger.getLogger(ISHAREAuthenticator.class);

    public static final String PROVIDER_ID = "client-ishare";

    private String keycloakOperatorPartyId;
    private String keycloakOperatorCert;
    private PrivateKey keycloakOperatorPrivateKey;
    
    private String iSHARESatellitePartyId;
    private String iSHARESatelliteBaseUrl;
    private X509Certificate iSHARE_CA;

    /* not working yet
    protected static final List<ProviderConfigProperty> configMetadata;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
                .property().name("ishare-config-file")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("iShareConfigFile")
                .defaultValue("${jboss.server.config.dir}/ishare.json")
                .helpText("iSHARE config file")
                .add().build();
    }
    */

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

    private String getParamsString(Map<String, String> params) throws java.io.UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
          result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
          result.append("=");
          result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
          result.append("&");
        }

        String resultString = result.toString();
        return resultString.length() > 0
          ? resultString.substring(0, resultString.length() - 1)
          : resultString;
    }

    private String createSatelliteClientAssertion()
    {
        Instant now = Instant.now();

        String jwt = Jwts.builder()
            .header()
            .add("typ", "JWT")
            .add("alg", "RS256")
            .add("x5c", keycloakOperatorCert)
            .and()
            .setAudience(iSHARESatellitePartyId)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now.plus(30L, ChronoUnit.SECONDS)))
            .setIssuer(keycloakOperatorPartyId)
            .setSubject(keycloakOperatorPartyId)
            .setNotBefore(Date.from(now))
            .setId(UUID.randomUUID().toString())
            .signWith(keycloakOperatorPrivateKey, Jwts.SIG.RS256)
            .compact();

        return jwt;
    }

    private String readBody(HttpURLConnection connection) throws Exception
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer content = new StringBuffer();
        while ((inputLine = reader.readLine()) != null) {
            content.append(inputLine);
        }
        reader.close();
        return content.toString();
    }
    
    private String getAccessTokenFromSatellite() throws Exception
    {
        String client_assertion = createSatelliteClientAssertion();
        log.tracef("Call Satellite with client_assertion: %s", client_assertion);

        String tokenURL = iSHARESatelliteBaseUrl.concat("/connect/token");

        URL url = new URL(tokenURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");        
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Accept", "application/json");
        
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        parameters.put("client_assertion", client_assertion);
        parameters.put("scope", "iSHARE");
        parameters.put("client_id", keycloakOperatorPartyId);

        connection.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(connection.getOutputStream());
        out.writeBytes(getParamsString(parameters));
        out.flush();
        out.close();

        int status = connection.getResponseCode();
        log.tracef("Satellite response status: %d", status);

        if (status == 200) {
            /* on success: 200 OK with { access_token, token_type, expires_in } */
            /* on missing client_assertion: 200 OK with { status: false, message } */
            String body = readBody(connection);

            ISHARESatelliteResponse resp = JsonSerialization.readValue(body, ISHARESatelliteResponse.class);
            if (resp.access_token == null || resp.access_token.isEmpty()) {
                // no access token means error
                log.errorf("Couldn't obtain token from Satellite: %s", resp.message != null ? resp.message : "unknown error");
                return null;
            }
            log.tracef("got access token: %s", resp.access_token);
            return resp.access_token;
        } else {
            log.errorf("Satellite returned error. Statuscode: %d", status);
            return null;
        }
    }

    private boolean verifyCallingPartyAtSatellite(String callingPartyId) throws Exception
    {
        String access_token = getAccessTokenFromSatellite();
        if (access_token == null) {
            return false;
        }

        //String tokenURL = iSHARESatelliteBaseUrl.concat(new String("/parties/").concat(callingPartyId));
        String tokenURL = iSHARESatelliteBaseUrl + "/parties/" + callingPartyId;
        log.tracef("call %s", tokenURL);

        URL url = new URL(tokenURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + access_token);
        connection.setRequestProperty("Accept", "application/json");
        connection.connect();
        
        int status = connection.getResponseCode();
        if (status != 200) {
            log.debugf("error getting parties: %d", status);
            return false;
        }

        String body = readBody(connection);

        ISHARESatellitePartiesResponse resp = JsonSerialization.readValue(body, ISHARESatellitePartiesResponse.class);

        if (!validatePartiesToken(resp.party_token, callingPartyId)) {
            log.error("Error validating parties token");
            return false;
        }
        
        return true;
    }

    private boolean validatePartiesToken(String partiesToken, String callingPartyId) throws Exception
    {
        log.trace("validate parties token");
        JWSInput jws = new JWSInput(partiesToken);
        if (!validateJwtCert(jws)) {
            log.error("Invalid parties token cert");
            return false;
        }

        JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
        if (!validateJwtToken(token)) {
            log.error("invalid parties token");
            return false;
        }

        byte[] contentBytes = Base64Url.decode(jws.getEncodedContent());

        log.tracef("token content: %s", new String(contentBytes));
        
        ISHAREPartyToken partyInfoToken = JsonSerialization.readValue(contentBytes, ISHAREPartyToken.class);

        if (!partyInfoToken.party_info.party_id.equals(callingPartyId)) {
            log.errorf("invalid party_id in party token: %s. Should be: %s", partyInfoToken.party_info.party_id, callingPartyId);
            return false;
        }

        if (!partyInfoToken.party_info.adherence.status.equals("Active")) {
            log.error("party not active");
            return false;
        }

        return true;
    }

    private boolean validateJwtToken(JsonWebToken token) throws Exception
    {
        if (!token.isActive()) {
            log.error("token is not active anymore");
            //return false; // skip for debugging
        }
            
        if (!token.hasAudience(keycloakOperatorPartyId)) {
            log.error("invalid aud");
            return false;
        }

        return true;
    }
    
    private boolean validateJwtCert(JWSInput jws) throws Exception
    {            
        // unfortunately no way to get x5c otherwise
        String encodedHeader = jws.getEncodedHeader();
        byte[] headerBytes = Base64Url.decode(encodedHeader);

        ISHAREJWSHeader header = JsonSerialization.readValue(headerBytes, ISHAREJWSHeader.class);

        String[] x5c = header.getX5C();
        if (x5c.length == 0) {
            log.error("x5c header value empty");
            return false;
        }
        log.trace("--- certs ----");
        for (String s : x5c) {
            log.tracef("x5c: %s", s);
        }
        log.trace("----------------");

        X509Certificate cert = PemUtils.decodeCertificate(x5c[0]);

        // Note: This works only if iSHARE_CA has full chain to root.
            
        cert.verify(iSHARE_CA.getPublicKey());

        return true;
    }

    private boolean validateClientAssertion(String client_assertion)
    {
        try {
            JWSInput jws = new JWSInput(client_assertion);
            if (!validateJwtCert(jws)) {
                return false;
            }

            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            if (!validateJwtToken(token)) {
                return false;
            }
            
            return verifyCallingPartyAtSatellite(token.getSubject());
        } catch (Exception e) {
            log.errorf("Exception validating client_assertion: %s", e.toString());
        }        
        return false;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);

        // TO-DO: If someone can figure out how we can use Config.Scope here,
        // please leave an Issue on Github. For now, we slurp a config json.

        try {
            String keycloakHome = System.getenv("KEYCLOAK_HOME");
            
            String configFilePath = (keycloakHome != null ? keycloakHome : ".") + "/conf/ishare.json";
            log.infof("use ishare config %s", configFilePath);
            
            String configFileContent = getFileContent(new FileInputStream(configFilePath), "utf-8");

            ISHAREAuthenticatorConfig cfg = JsonSerialization.readValue(configFileContent, ISHAREAuthenticatorConfig.class);

            keycloakOperatorPartyId = cfg.operatorId;
            iSHARESatellitePartyId = cfg.satelliteId;
            iSHARESatelliteBaseUrl = cfg.satelliteUrl;

            FileInputStream inStream = new FileInputStream(cfg.ishareCaFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            iSHARE_CA = (X509Certificate) cf.generateCertificate(inStream);

            keycloakOperatorCert = getFileContent(new FileInputStream(cfg.certFile), "utf-8")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END CERTIFICATE-----", "");

            String privKeyTmp = getFileContent(new FileInputStream(cfg.pkFile), "utf-8");
            String privateKeyPEM = privKeyTmp
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            KeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            keycloakOperatorPrivateKey = keyFactory.generatePrivate(keySpec);

            // to-do: Would be nice to crash that thing when the ca file cant be loaded so that
            // Keycloak doesn't start. But how :-)
        } catch (Exception e) {
            log.errorf("Exception during init %s", e.toString());
        }

        log.info("ISHAREAuthenticator init done");
    }

    public static String getFileContent(FileInputStream fis, String encoding ) throws IOException
    {
        try (BufferedReader br = new BufferedReader( new InputStreamReader(fis, encoding )))
            {
                StringBuilder sb = new StringBuilder();
                String line;
                while(( line = br.readLine()) != null ) {
                    sb.append( line );
                    sb.append( '\n' );
                }
                return sb.toString();
            }
    }

    @Override
    public String getDisplayType() {
        return "iSHARE";
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        // doesnt seem to work yet:
        // https://keycloak.discourse.group/t/custom-per-client-configurable-clientauthenticator/24226
        // return configMetadata;
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
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
