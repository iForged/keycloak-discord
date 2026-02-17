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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class DiscordIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public static final String ALLOWED_GUILDS = "allowedGuilds";
    public static final String MAPPED_ROLES = "mappedRoles";
    public static final String PROMPT_NONE = "promptNone";
    public static final String PROMPT = "prompt";

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
                .collect(Collectors.joining(", "));

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

    public String getMappedRoles() {
        return getConfig().get(MAPPED_ROLES);
    }

    public void setMappedRoles(String mappedRoles) {
        getConfig().put(MAPPED_ROLES, mappedRoles);
    }

    public boolean hasMappedRoles() {
        String mappedRoles = getConfig().get(MAPPED_ROLES);
        return mappedRoles != null && !mappedRoles.trim().isEmpty();
    }

    public Map<String, HashMap<String, String>> getMappedRolesAsMap() {
        if (!hasMappedRoles()) {
            return Collections.emptyMap();
        }

        String mappedRolesStr = getMappedRoles();
        Map<String, HashMap<String, String>> parsed = new HashMap<>();

        for (String entry : mappedRolesStr.split(",")) {
            entry = entry.trim();
            if (entry.isEmpty()) continue;

            String[] parts = entry.split(":", 3);
            if (parts.length != 3) continue;

            String guildId = parts[0].trim();
            String roleOrGuildId = parts[1].trim();
            String groupName = parts[2].trim();

            if (groupName.isEmpty()) continue;

            parsed.computeIfAbsent(guildId, k -> new HashMap<>())
                  .put(roleOrGuildId, groupName);
        }

        return parsed;
    }

    public String getPrompt() {
        return getConfig().get(PROMPT);
    }

    public void setPrompt(String prompt) {
        getConfig().put(PROMPT, prompt);
    }

    public boolean isPromptNone() {
        String value = getConfig().get(PROMPT_NONE);
        return value != null && Boolean.parseBoolean(value);
    }

    public void setPromptNone(boolean promptNone) {
        getConfig().put(PROMPT_NONE, String.valueOf(promptNone));
    }
}
