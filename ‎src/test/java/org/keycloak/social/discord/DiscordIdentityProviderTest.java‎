package org.keycloak.social.discord;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscordIdentityProviderTest {

    DiscordIdentityProvider provider;

    ObjectMapper mapper;

    @Mock
    KeycloakSession session;

    @Mock
    DiscordIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        when(config.getAlias()).thenReturn("discord");

        provider = new DiscordIdentityProvider(session, config);

        mapper = new ObjectMapper();
    }

    @Test
    void testNameDiscriminatorHandling() throws Exception {
        String jsonProfileLegacy = """
{
  "id": "80351110224678912",
  "username": "Nelly",
  "discriminator": "1337",
  "email": "nelly@discord.com"
}
        """;
        JsonNode profile = mapper.readTree(jsonProfileLegacy);
        BrokeredIdentityContext user = provider.extractIdentityFromProfile(null, profile);

        assertEquals("80351110224678912", user.getId());
        assertEquals("nelly#1337", user.getUsername());

    }

    @Test
    void testNameDiscriminatorHandling_NoDiscriminator() throws Exception {
        String jsonProfileNew = """
{
  "id": "80351110224678912",
  "username": "nelly",
  "discriminator": "0",
  "email": "nelly@discord.com"
}
        """;
        JsonNode profile = mapper.readTree(jsonProfileNew);
        BrokeredIdentityContext user = provider.extractIdentityFromProfile(null, profile);

        assertEquals("80351110224678912", user.getId());
        assertEquals("nelly", user.getUsername());
        assertEquals("nelly@discord.com", user.getEmail());

    }

    @Test
    void testExtractIdentity_NoAvatar() throws Exception {
        String jsonProfile = """
{
  "id": "80351110224678912",
  "username": "nelly",
  "discriminator": "0",
  "email": "nelly@discord.com"
}
        """;
        JsonNode profile = mapper.readTree(jsonProfile);

        BrokeredIdentityContext user = provider.extractIdentityFromProfile(null, profile);

        assertNull(user.getUserAttribute("picture"));

    }

    @Test
    void testExtractIdentity_WithStaticAvatar() throws Exception {
        String jsonProfile = """
{
  "id": "80351110224678912",
  "username": "nelly",
  "discriminator": "0",
  "avatar": "8342729096ea3675442027381ff50dfe",
  "email": "nelly@discord.com"
}
        """;
        JsonNode profile = mapper.readTree(jsonProfile);

        BrokeredIdentityContext user = provider.extractIdentityFromProfile(null, profile);

        String expectedURL = "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png?size=256";
        assertEquals(expectedURL, user.getUserAttribute("picture"));

    }

    @Test
    void testExtractIdentity_WithAnimatedAvatar() throws Exception {
        String jsonProfile = """
{
  "id": "80351110224678912",
  "username": "nelly",
  "discriminator": "0",
  "avatar": "a_8342729096ea3675442027381ff50dfe",
  "email": "nelly@discord.com"
}
        """;
        JsonNode profile = mapper.readTree(jsonProfile);

        BrokeredIdentityContext user = provider.extractIdentityFromProfile(null, profile);

        String expectedURL = "https://cdn.discordapp.com/avatars/80351110224678912/a_8342729096ea3675442027381ff50dfe.gif?size=256";
        assertEquals(expectedURL, user.getUserAttribute("picture"));

    }
}
