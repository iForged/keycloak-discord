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

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.util.JsonSerialization;

import java.util.List;
import java.util.Map;

public class DiscordIdentityProviderFactory
        extends AbstractIdentityProviderFactory<DiscordIdentityProvider>
        implements SocialIdentityProviderFactory {

    public static final String PROVIDER_ID = "discord";

    @Override
    public String getName() {
        return "Discord";
    }

    @Override
    public DiscordIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        DiscordIdentityProviderConfig config = new DiscordIdentityProviderConfig(model);
        if (config.isPromptNone()) {
            config.setPrompt("none");
        }
        return new DiscordIdentityProvider(session, config);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(DiscordIdentityProviderConfig.ALLOWED_GUILDS)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Guild Id(s) to allow federation")
                .helpText("If you want to allow federation for specific guild, enter the guild id. Please use a comma as a separator for multiple guilds.")
                .add()

                .property()
                .name(DiscordIdentityProviderConfig.PROMPT_NONE)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Skip Discord prompt (prompt=none)")
                .helpText("If enabled, adds 'prompt=none' to the authorization URL. This skips the Discord consent screen for users who have already authorized the application (useful for seamless login).")
                .defaultValue(Boolean.FALSE)
                .add()

                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String json) {
        try {
            return JsonSerialization.readValue(json, Map.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse provider configuration", e);
        }
    }
}
