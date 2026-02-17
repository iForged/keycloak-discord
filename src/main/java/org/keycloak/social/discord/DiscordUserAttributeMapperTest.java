package org.keycloak.social.discord;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DiscordUserAttributeMapperTest {
    @Test
    void getCompatibleProviders() {
         DiscordUserAttributeMapper mapper = new DiscordUserAttributeMapper();
         String[] providers = mapper.getCompatibleProviders();
         assertNotNull(providers);
         assertNotEquals(0, providers.length);
    }

}
