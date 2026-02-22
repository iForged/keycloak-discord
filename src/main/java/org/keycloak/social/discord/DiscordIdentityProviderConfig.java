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

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.*;
import java.util.stream.Collectors;

public class DiscordIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public static final String ALLOWED_GUILDS = "allowedGuilds";
    public static final String DISCORD_ROLE_MAPPING = "discord_role_mapping";
    public static final String PROMPT_NONE = "promptNone";

    public DiscordIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public DiscordIdentityProviderConfig() {
    }

    public String getAllowedGuilds() {
        return getConfig().get(ALLOWED_GUILDS);
    }

    public void setAllowedGuilds(String allowedGuilds) {
        if (allowedGuilds == null || allowedGuilds.trim().isEmpty()) {
            getConfig().remove(ALLOWED_GUILDS);
            return;
        }
        String cleaned = Arrays.stream(allowedGuilds.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.joining(","));
        getConfig().put(ALLOWED_GUILDS, cleaned);
    }

    public boolean hasAllowedGuilds() {
        String guilds = getConfig().get(ALLOWED_GUILDS);
        return guilds != null && !guilds.trim().isEmpty();
    }

    public Set<String> getAllowedGuildsAsSet() {
        String guilds = getConfig().get(ALLOWED_GUILDS);
        if (guilds == null || guilds.trim().isEmpty()) {
            return Collections.emptySet();
        }
        return Arrays.stream(guilds.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    public String getDiscordRoleMapping() {
        return getConfig().get(DISCORD_ROLE_MAPPING);
    }

    public void setDiscordRoleMapping(String mapping) {
        if (mapping == null || mapping.trim().isEmpty()) {
            getConfig().remove(DISCORD_ROLE_MAPPING);
        } else {
            getConfig().put(DISCORD_ROLE_MAPPING, mapping);
        }
    }

    public boolean hasDiscordRoleMapping() {
        String mapping = getDiscordRoleMapping();
        return mapping != null && !mapping.trim().isEmpty();
    }

    public Map<String, Map<String, String>> getDiscordRoleMappingAsMap() {
        String text = getDiscordRoleMapping();
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, Map<String, String>> result = new HashMap<>();

        String[] lines = text.split("\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split(":", -1);
            if (parts.length != 3) {
                continue;
            }

            String guildId = parts[0].trim();
            String roleId = parts[1].trim();
            String groupName = parts[2].trim();

            if (guildId.isEmpty() || groupName.isEmpty()) {
                continue;
            }

            result.computeIfAbsent(guildId, k -> new HashMap<>())
                  .put(roleId, groupName);
        }

        return result;
    }

    public boolean isPromptNone() {
        String value = getConfig().get(PROMPT_NONE);
        return value != null && Boolean.parseBoolean(value);
    }

    public void setPromptNone(boolean promptNone) {
        getConfig().put(PROMPT_NONE, String.valueOf(promptNone));
    }
}
