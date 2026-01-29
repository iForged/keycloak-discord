# keycloak-discord

Keycloak Social Login extension for Discord (OAuth2 Identity Provider).

**This is an actively maintained fork** of the original repository  
https://github.com/wadahiro/keycloak-discord  
which has not been updated since November 2024 and has lost relevance for newer Keycloak versions (especially 26.0.5+).

Main improvements in this fork:
- Full compatibility with Keycloak up to version 26.5.2
- Support for `prompt` parameter (e.g. `prompt=none` for better repeated login UX)
- Java 21 support
- Clean code, updated dependencies, CI/CD with GitHub Actions

## Install

Download `keycloak-discord-<version>.jar` from [Releases page](https://github.com/iForged/keycloak-discord/releases).
Then deploy it into `$KEYCLOAK_HOME/providers` directory.

## Setup
Discord Developer Portal
```
1. Go to https://discord.com/developers/applications
2. Create a new application
3. In OAuth2 → General → Add redirect URI:
4. https://your-keycloak/auth/realms/your-realm/broker/discord/endpoint
5. Copy Client ID and Client Secret
```
Keycloak Admin Console
```
1. Go to your realm → Identity Providers → Add provider → Discord
2. Fill in Client ID and Client Secret
3. (Optional) Enter Guild ID(s) (comma-separated) to restrict access only to members of specific Discord servers
4. (Optional) Set Prompt parameter (e.g. none to skip consent screen on repeated logins)
5. Save and test the login button
```
Note: You don't need to setup the theme in `master` realm from v0.3.0.

## Docker Deployment (Recommended)
```
FROM curlimages/curl:8.11.1 AS download

# Replace <version> with actual version, e.g. 1.1.0
RUN mkdir -p ~/download && \
    curl -L -o ~/download/keycloak-discord-<version>.jar \
    https://github.com/iForged/keycloak-discord/releases/download/<version>/keycloak-discord-<version>.jar

FROM quay.io/keycloak/keycloak:26.5.2

USER root

# Optional: if you have custom CA certificates (e.g. for LDAP SSL)
# COPY data/ssl/LDAPssl.cer /etc/pki/ca-trust/source/anchors/
# RUN update-ca-trust

USER 1000

# Copy the provider JAR from the download stage
COPY --from=download /home/curl_user/download/keycloak-discord.jar \
     /opt/keycloak/providers/keycloak-discord.jar

# Build optimized image with the provider
RUN /opt/keycloak/bin/kc.sh build

# Run Keycloak
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
```
Tips:
- Replace `<version>` with real tag (e.g. `1.1.0`)
- Use `--optimized` in CMD for production (faster startup)
- Mount your own `conf/keycloak.conf` or use environment variables for configuration


## Source Build

Clone this repository and run `mvn package`.
You can see `keycloak-discord-<version>.jar` under `target` directory.


## Licence

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)


## Original Author

- [Hiroyuki Wada](https://github.com/wadahiro)

## Fork Author
- Fork maintained by [iForged](https://github.com/iForged)


