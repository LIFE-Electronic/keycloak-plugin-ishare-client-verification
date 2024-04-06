# iSHARE Client Authenticator Plugin

Maintainer: markus (at) life-electronic (dot) nl

This Keycloak plugin implements the Client Authenticator Flow for
iSHARE.

Tested with Keycloak-24.0.2.

## Installation

Compile the plugin and copy or symlink the jar into the providers directory of
Keycloak.

To compile it, use Java SDK >= 17 and < 22. Then run `mvn clean package` in the
main directory. This will create the jar:
`target/ishare-client-authenticator-plugin-1.0-SNAPSHOT.jar`. 

## Configuration

To function properly, this plugin requires a config file. The config
file is `${KEYCLOAK_HOME}/conf/ishare.conf`. 

The config must look like this. All fields are mandatory.
```
{
    "operator-id": "<EORI of the party that operates Keycloak>",
    "operator-cert-file": "<path to your party cert>",
    "operator-pk-file": "<path to your party private key>",
    "satellite-id": "<EORI of satellite",
    "satellite-url": "<sat url>",
    "ishare-ca-file": "<path to ishare-ca-file>"
}
```

### Cert files

#### ishare-ca-file

The iSHARE ca-file can be obtained from iSHARE. Must include the whole
chain to the root.

#### operator-cert-file

The cert of the party that operates Keycloak. 

```
-----BEGIN CERTIFICATE-----
<base64 encoded cert>
-----END CERTIFICATE-----
```

#### operator-pk-file

The pk key of the party that operates Keycloak.
```
-----BEGIN PRIVATE KEY-----
<base64 encoded private key>
-----END PRIVATE KEY-----
```

### Notes

1. Unfortunately it is not yet possible to do a per-client
config. If someone can help fix this, please reach out :-).

2. If `KEYCLOAK_HOME` isn't set, the plugin will try
   `./conf/ishare.conf` relative to your pwd.

## Setup

### Create Realm

Create Realm. Make sure that **Unmanaged Attributes** is enabled.

### Create Client

To setup the plugin in Keycloak, first generate a new Client for your
Realm. The **Client ID** should be your EORI (`operator-id` from the
config). 
Set **Client Authentication** to ON and only enable Standard
Flow. Also enable **Consent Required**.

Go to *Credentials* tab and select `iSHARE`. Click on *SAVE*.
Go to *Advanced* and set **User info signed response algorithm** to
`RSA256`. Click on *SAVE*.

Note: This will force Keycloak to return the a jwt in the `/userinfo`
called. This response is **NOT YET** signed with the cert. We are
working on it!

### Setup login flow

Next, go to *Configure->Authentication* and click on *Flows*. Then
create a new flow with name `ishare` and add a new Step. Select the
`iSHARE` plugin. Set **Requirement** to *Required*.

Go back to *Configure->Authentication->Flows* and bind the `ishare` flow
to the *Client authentication flow* (click on the three dots on the
right).

### Add iSHARE scope

Next, create a scope called `ishare` with the following settings:

- Type: Default
- Display on consent screen: On
- Consent screen text: iSHARE Details (or what you want).
- Include in token scope: On

After the scope is created, go to tab *Mappers*. Click on *Configure a
new mapper*. Click on *User Attribute*. Use the following settings:

- Name: `companyId`
- User Attribute: `companyId`
- Token Claim Name: `company_id`

Save and do the same for `companyName`/`company_name`.

Go back to your client and in tab *Client Scopes*, add the scope as a
**Default** scope.

### Create first user

Now we create the first user. Make sure to add the attributes `companyId`
and `companyName`. `companyId` should be the EORI of the users org and
`companyName` its display name.

## How to login

The login flow is essentially a standard OIDC flow. Set `scope` to `openid`, Leave `Client Secret`
empty. In the Token Request step, add the iSHARE `client_assertion` in
the Request Body.

## DEBUG

If you want to debug it, set log level for the plugin to TRACE or
DEBUG. E.g. `--log-level="com.life:DEBUG`






   




