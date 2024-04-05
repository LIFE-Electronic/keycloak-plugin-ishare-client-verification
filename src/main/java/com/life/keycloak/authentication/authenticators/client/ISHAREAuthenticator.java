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
        //PrivateKey privateKey = new PrivateKey();
        Instant now = Instant.now();

        String jwt = Jwts.builder()
            .header()
            .add("x5c", keycloakOperatorCert)
            .and()
            .setAudience(iSHARESatellitePartyId)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now.plus(30L, ChronoUnit.SECONDS)))
            .setIssuer(keycloakOperatorPartyId)
            .setSubject(keycloakOperatorPartyId)
            .setNotBefore(Date.from(now))
            .setId(UUID.randomUUID().toString())
            .signWith(keycloakOperatorPrivateKey)
            .compact();

        return jwt;
    }
    
    private String getAccessTokenFromSatellite() throws Exception
    {
        String grant_type = "client_credentials";
        String client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        String client_id = keycloakOperatorPartyId;
        String scope = "iSHARE";
        String client_assertion = createSatelliteClientAssertion();
        log.debugf("Call Satellite with client_assertion: %s", client_assertion);

        String tokenURL = iSHARESatelliteBaseUrl.concat("/connect/token");

        URL url = new URL(tokenURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");        
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Accept", "application/json");
        
        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", grant_type);
        parameters.put("client_assertion_type", client_assertion_type);
        parameters.put("client_assertion", client_assertion);
        parameters.put("scope", scope);
        parameters.put("client_id", client_id);

        connection.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(connection.getOutputStream());
        out.writeBytes(getParamsString(parameters));
        out.flush();
        out.close();

        int status = connection.getResponseCode();
        log.debugf("Satellite response status: %d", status);

        if (status == 200) {
            /* on success: 200 OK with { access_token, token_type, expires_in } */
            /* on missing client_assertion: 200 OK with { status: false, message } */
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = reader.readLine()) != null) {
                content.append(inputLine);
            }
            reader.close();

            log.debugf("iSHARE Response: %s", content.toString());
            
            ISHARESatelliteResponse resp = JsonSerialization.readValue(content.toString(), ISHARESatelliteResponse.class);
            if (resp.access_token == null || resp.access_token.isEmpty()) {
                // no access token means error
                log.errorf("Couldn't obtain token from Satellite: %s", resp.message != null ? resp.message : "unknown error");
                return null;
            }
            return resp.access_token;
        } else {
            log.errorf("Satellite returned error. Statuscode: %d", status);
            return null;
        }
    }

    private boolean verifyCallingPartyAtSatellite(String callingPartyId) throws Exception
    {
        String access_token = getAccessTokenFromSatellite();

        return true;
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

            X509Certificate cert = PemUtils.decodeCertificate(x5c[0]);

            //List<X509Certificate> chain = new ArrayList<>();
            //chain.add(cert);

            cert.verify(iSHARE_CA.getPublicKey());
            
            if (!token.isActive()) {
                log.error("token is not active anymore");
                // return false; // skip for debugging
            }
            
            if (!token.hasAudience(keycloakOperatorPartyId)) {
                log.error("invalid aud");
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

        //String test = config.get("testval", "");
        //log.debugf("TEST CONFIG VAL: %s", test);
        
        keycloakOperatorPartyId = "NL.EORI.LIFEELEC4DMI";
        iSHARESatellitePartyId = "EU.EORI.NLDEXESDMISAT1";
        iSHARESatelliteBaseUrl = "https://satellite-mw.dev.dexes.eu";

        try {
            String ca_file = "/home/markus/clients/dexes/ishare_certs/TESTiSHAREEUIssuingCertificationAuthorityG5-chain.pem";
            //String u = "/home/markus/clients/dexes/ishare_certs/Test_iSHARE_EU_Issuing_Certification_Authority_G5.pem";
            FileInputStream inStream = new FileInputStream(ca_file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            iSHARE_CA = (X509Certificate) cf.generateCertificate(inStream);

            String op_cert_file = "/home/markus/clients/dexes/ishare_certs/lifecert.crt";
            String op_key_file = "/home/markus/clients/dexes/ishare_certs/lifekey.pem";

            keycloakOperatorCert = getFileContent(new FileInputStream(op_cert_file), "utf-8")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END CERTIFICATE-----", "");

            String privKeyTmp = getFileContent(new FileInputStream(op_key_file), "utf-8");
            String privateKeyPEM = privKeyTmp
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            KeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            //KeySpec keySpec = new RSAPrivateKeySpec(encoded);
            keycloakOperatorPrivateKey = keyFactory.generatePrivate(keySpec);

            log.debugf("keycloakOperatorCert :\n%s\n", op_cert_file);

            // to-do: Would be nice to crash that thing when the ca file cant be loaded.
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
