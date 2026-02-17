package org.keycloak.social.discord;

import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DiscordIdentityProviderConfigTest {

    @Test
    void given_noAllowedGuilds_expect_emptyResult() {
        IdentityProviderModel model = new IdentityProviderModel();
        DiscordIdentityProviderConfig config = new DiscordIdentityProviderConfig(model);

        assertFalse(config.hasAllowedGuilds());

        config.setAllowedGuilds("");
        assertFalse(config.hasAllowedGuilds());
        assertTrue(config.getAllowedGuildsAsSet().isEmpty());

        config.setAllowedGuilds("   ");
        assertFalse(config.hasAllowedGuilds());
        assertTrue(config.getAllowedGuildsAsSet().isEmpty());

        config.setAllowedGuilds(",,,");
        assertFalse(config.hasAllowedGuilds());
        assertTrue(config.getAllowedGuildsAsSet().isEmpty());

        config.setAllowedGuilds(",  ,,    ,  ,");
        assertFalse(config.hasAllowedGuilds());
        assertTrue(config.getAllowedGuildsAsSet().isEmpty());
    }

    @Test
    void given_allowedGuildsPresent_expect_results() {
        List<String> guilds = List.of("0123456789123456789", "9876543210987654321");
        String guildsAsString = "0123456789123456789,9876543210987654321";

        IdentityProviderModel model = new IdentityProviderModel();
        DiscordIdentityProviderConfig config = new DiscordIdentityProviderConfig(model);

        String expectedGuild = guilds.get(0);
        config.setAllowedGuilds(expectedGuild);
        assertTrue(config.hasAllowedGuilds());
        assertEquals(1, config.getAllowedGuildsAsSet().size());
        assertTrue(config.getAllowedGuildsAsSet().contains(expectedGuild));
        assertEquals(expectedGuild, config.getAllowedGuilds());

        config.setAllowedGuilds("," + expectedGuild + ",,");
        assertTrue(config.hasAllowedGuilds());
        assertEquals(1, config.getAllowedGuildsAsSet().size());
        assertTrue(config.getAllowedGuildsAsSet().contains(expectedGuild));

        config.setAllowedGuilds(String.join(",", guilds));
        assertTrue(config.hasAllowedGuilds());
        assertEquals(guilds.size(), config.getAllowedGuildsAsSet().size());
        assertTrue(config.getAllowedGuildsAsSet().containsAll(guilds));
        assertEquals(guildsAsString, config.getAllowedGuilds());

        config.setAllowedGuilds(String.join(", ,, ,   ,", guilds));
        assertTrue(config.hasAllowedGuilds());
        assertEquals(guilds.size(), config.getAllowedGuildsAsSet().size());
        assertTrue(config.getAllowedGuildsAsSet().containsAll(guilds));
        assertEquals(guildsAsString, config.getAllowedGuilds());
    }
}
