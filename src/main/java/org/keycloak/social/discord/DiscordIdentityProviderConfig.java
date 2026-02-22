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

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class DiscordIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public DiscordIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public DiscordIdentityProviderConfig() {
    }

    public String getAllowedGuilds() {
        return getConfig().get("allowedGuilds");
    }

    public boolean setPromptNone() {
        if(getConfig().containsKey("promptNone")) {
            return true;
        } else {
            return false;
        }
    }

    public void setAllowedGuilds(String allowedGuilds) {
        getConfig().put("allowedGuilds", allowedGuilds);
    }

    public boolean hasAllowedGuilds() {
        String guilds = getConfig().get("allowedGuilds");
        return guilds != null && !guilds.trim().isEmpty();
    }

    public Set<String> getAllowedGuildsAsSet() {
        if (hasAllowedGuilds()) {
            String guilds = getConfig().get("allowedGuilds");
            return Arrays.stream(guilds.split(",")).map(x -> x.trim()).collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    public String getMappedRoles() {
        return getConfig().get("mappedRoles");
    }

    public void setMappedRoles(String mappedRoles) {
        getConfig().put("mappedRoles", mappedRoles);
    }

    public boolean hasMappedRoles() {
        String mappedRoles = getConfig().get("mappedRoles");
        return mappedRoles != null && !mappedRoles.trim().isEmpty();
    }

    public Map<String, HashMap<String, String>> getMappedRolesAsMap() {
        if (hasMappedRoles()) {
            String mappedRoles = getMappedRoles();
            Map<String, HashMap<String, String>> parsedRoles = new HashMap<>();
            for (String rawRole : mappedRoles.split(",")) {
                rawRole = rawRole.trim();
                String fragments[] = rawRole.split(":");
                if (fragments.length != 3) {
                    continue;
                }
                if (!parsedRoles.containsKey(fragments[0])) {
                    parsedRoles.put(fragments[0], new HashMap<>());
                }
                parsedRoles.get(fragments[0]).put(fragments[1], fragments[2]);
            }
            return parsedRoles;
        }
        return Collections.emptyMap();
    }

    public void setPrompt(String prompt) {
        getConfig().put("prompt", prompt);
    }
}
