/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.discord;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class DiscordIdentityProvider 
        extends AbstractOAuth2IdentityProvider<DiscordIdentityProviderConfig>
        implements SocialIdentityProvider<DiscordIdentityProviderConfig>,
                   UserAuthenticationIdentityProvider<DiscordIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(DiscordIdentityProvider.class);

    public static final String AUTH_URL = "https://discord.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://discord.com/api/oauth2/token";
    public static final String PROFILE_URL = "https://discord.com/api/users/@me";
    public static final String GROUP_URL = "https://discord.com/api/users/@me/guilds";
    public static final String GUILD_MEMBER_URL = "https://discord.com/api/users/@me/guilds/%s/member";

    public static final String DEFAULT_SCOPE = "identify email";
    public static final String GUILDS_SCOPE = "guilds";
    public static final String ROLES_SCOPE = "guilds.members.read";

    public DiscordIdentityProvider(KeycloakSession session, DiscordIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
        if (config.setPromptNone()) {
            config.setPrompt("none");
        }
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"), getConfig());
        String username = getJsonProperty(profile, "username");
        String discriminator = getJsonProperty(profile, "discriminator");

        if (!"0".equals(discriminator)) {
            username += "#" + discriminator;
        }

        user.setUsername(username);
        user.setEmail(getJsonProperty(profile, "email"));
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        log.debug("doGetFederatedIdentity()");
        JsonNode profile;

        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session)
                    .header("Authorization", "Bearer " + accessToken)
                    .asJson();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from discord.", e);
        }

        if (getConfig().hasAllowedGuilds()) {
            if (!isAllowedGuild(accessToken)) {
                throw new ErrorPageException(session, Response.Status.FORBIDDEN, Messages.INVALID_REQUESTER);
            }
        }

        ArrayNode groups = JsonNodeFactory.instance.arrayNode();

        if (getConfig().hasMappedRoles()) {
            Map<String, HashMap<String, String>> mappedRoles = getConfig().getMappedRolesAsMap();

            for (String guildId : mappedRoles.keySet()) {
                JsonNode guildMember;
                try {
                    guildMember = SimpleHttp.doGet(String.format(GUILD_MEMBER_URL, guildId), session)
                            .header("Authorization", "Bearer " + accessToken)
                            .asJson();

                    if (guildMember.has("joined_at")) {
                        if (mappedRoles.get(guildId).containsKey(guildId)) {
                            groups.add(mappedRoles.get(guildId).get(guildId));
                        }

                        JsonNode rolesNode = guildMember.get("roles");
                        if (rolesNode != null && rolesNode.isArray()) {
                            for (JsonNode role : rolesNode) {
                                String roleId = role.textValue();
                                if (mappedRoles.get(guildId).containsKey(roleId)) {
                                    groups.add(mappedRoles.get(guildId).get(roleId));
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.debugf("Could not obtain guild member data for guild %s from Discord: %s", guildId, e.getMessage());
                }
            }
        }

        if (profile instanceof ObjectNode) {
            ((ObjectNode) profile).set("discord-groups", groups);
        }

        return extractIdentityFromProfile(null, profile);
    }

    protected boolean isAllowedGuild(String accessToken) {
        try {
            JsonNode guilds = SimpleHttp.doGet(GROUP_URL, session)
                    .header("Authorization", "Bearer " + accessToken)
                    .asJson();

            Set<String> allowedGuilds = getConfig().getAllowedGuildsAsSet();

            for (JsonNode guild : guilds) {
                String guildId = getJsonProperty(guild, "id");
                if (allowedGuilds.contains(guildId)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain guilds the current user is a member of from discord.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        String scopes = DEFAULT_SCOPE;

        if (getConfig().hasAllowedGuilds()) {
            scopes += " " + GUILDS_SCOPE;
        }
        if (getConfig().hasMappedRoles()) {
            scopes += " " + ROLES_SCOPE;
        }

        return scopes;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        String prompt = getConfig().getPrompt();

        if (prompt != null && !prompt.trim().isEmpty()) {
            uriBuilder.queryParam("prompt", prompt.trim());
            log.debugf("Added prompt=%s to Discord authorization URL", prompt.trim());
        }

        return uriBuilder;
    }
}