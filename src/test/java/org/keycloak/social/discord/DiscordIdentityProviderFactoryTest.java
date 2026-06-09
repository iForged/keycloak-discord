package org.keycloak.social.discord;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DiscordIdentityProviderFactoryTest {

    @Test
    void getId_shouldReturnDiscord() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();
        assertEquals("discord", factory.getId());
    }

    @Test
    void getName_shouldBeNonEmpty() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();
        String name = factory.getName();
        assertNotNull(name);
        assertFalse(name.isBlank());
    }

    @Test
    void createConfig_shouldReturnDiscordConfig() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();
        assertInstanceOf(DiscordIdentityProviderConfig.class, factory.createConfig());
    }

    @Test
    void getConfigProperties_shouldContainDiscordSpecificFields() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();
        List<ProviderConfigProperty> props = factory.getConfigProperties();
        assertNotNull(props);

        List<String> names = props.stream().map(ProviderConfigProperty::getName).toList();
        assertTrue(names.contains(DiscordIdentityProviderConfig.ALLOWED_GUILDS), "Should have allowedGuilds");
        assertTrue(names.contains(DiscordIdentityProviderConfig.DISCORD_ROLE_MAPPING), "Should have discord_role_mapping");
        assertTrue(names.contains(DiscordIdentityProviderConfig.PROMPT_NONE), "Should have promptNone");
    }

    @Test
    void getConfigProperties_shouldNotContainAcceptsPromptNone() {
        DiscordIdentityProviderFactory factory = new DiscordIdentityProviderFactory();
        List<ProviderConfigProperty> props = factory.getConfigProperties();

        boolean hasBuiltinPromptNone = props.stream()
                .anyMatch(p -> "acceptsPromptNoneForwardFromClient".equals(p.getName()));
        assertFalse(hasBuiltinPromptNone,
                "Built-in 'acceptsPromptNoneForwardFromClient' should be removed to avoid duplicate prompt settings in UI");
    }
}
