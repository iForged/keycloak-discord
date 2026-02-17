package org.keycloak.social.discord;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DiscordIdentityProviderFactoryTest {

    @Test
    void getName() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();

        String name = factory.getName();
        assertNotNull(name);
        assertNotEquals(0, name.length());
    }

}
