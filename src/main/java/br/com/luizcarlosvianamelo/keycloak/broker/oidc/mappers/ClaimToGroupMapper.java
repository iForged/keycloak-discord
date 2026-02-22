package br.com.luizcarlosvianamelo.keycloak.broker.oidc.mappers;

import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.social.discord.DiscordIdentityProviderFactory;

import java.util.*;
import java.util.stream.Collectors;

public class ClaimToGroupMapper extends AbstractClaimMapper {

    private static final Logger logger = Logger.getLogger(ClaimToGroupMapper.class);

    public static final String PROVIDER_ID = "claim-to-group-mapper";

    private static final String[] COMPATIBLE_PROVIDERS = {
            KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            OIDCIdentityProviderFactory.PROVIDER_ID,
            DiscordIdentityProviderFactory.PROVIDER_ID
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    private static final String CLAIM = "claim";
    private static final String CONTAINS_TEXT = "contains_text";
    private static final String CREATE_GROUPS = "create_groups";
    private static final String CLEAR_ROLES_IF_NONE = "clearRolesIfNone";

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(CLAIM);
        property.setLabel("Claim");
        property.setHelpText("Name of claim containing groups (usually 'discord-groups' for Discord provider). Supports nested paths with '.' (escape literal dot with \\.)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CONTAINS_TEXT);
        property.setLabel("Contains text");
        property.setHelpText("Only synchronize groups containing this substring. Leave empty to sync all.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CREATE_GROUPS);
        property.setLabel("Create groups if not exists");
        property.setHelpText("Automatically create groups in realm if they don't exist.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLEAR_ROLES_IF_NONE);
        property.setLabel("Clear groups if no groups found");
        property.setHelpText("Remove all synced groups if claim is empty or no groups matched.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Group Importer";
    }

    @Override
    public String getDisplayType() {
        return "Claim to Group Mapper";
    }

    @Override
    public String getHelpText() {
        return "Synchronizes groups from IdP claim (array of strings) to Keycloak realm groups.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        syncGroups(session, realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        syncGroups(session, realm, user, mapperModel, context);
    }

    private void syncGroups(KeycloakSession session, RealmModel realm, UserModel user,
                            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        String claimName = mapperModel.getConfig().get(CLAIM);
        if (claimName == null || claimName.trim().isEmpty()) {
            return;
        }

        String containsText = mapperModel.getConfig().get(CONTAINS_TEXT);
        boolean createGroups = Boolean.parseBoolean(mapperModel.getConfig().get(CREATE_GROUPS));
        boolean clearIfNone = Boolean.parseBoolean(mapperModel.getConfig().get(CLEAR_ROLES_IF_NONE));

        List<String> claimGroups = getClaimValue(context, claimName);

        if (claimGroups.isEmpty() && !clearIfNone) {
            return;
        }

        Set<String> desired = claimGroups.stream()
                .filter(t -> containsText == null || containsText.isEmpty() || t.contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> current = user.getGroupsStream()
                .filter(g -> containsText == null || containsText.isEmpty() || g.getName().contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> target = getOrCreateGroups(session, realm, desired, createGroups);

        Set<GroupModel> toRemove = new HashSet<>(current);
        toRemove.removeAll(target);

        Set<GroupModel> toAdd = new HashSet<>(target);
        toAdd.removeAll(current);

        toRemove.forEach(user::leaveGroup);
        toAdd.forEach(user::joinGroup);
    }

    private Set<GroupModel> getOrCreateGroups(KeycloakSession session, RealmModel realm,
                                              Set<String> names, boolean create) {
        Set<GroupModel> groups = new HashSet<>();
        for (String name : names) {
            GroupModel group = session.groups().getGroupByName(realm, null, name);
            if (group == null && create) {
                group = session.groups().createGroup(realm, name);
            }
            if (group != null) {
                groups.add(group);
            }
        }
        return groups;
    }

    public static List<String> getClaimValue(BrokeredIdentityContext context, String claim) {
        JsonNode profile = (JsonNode) context.getContextData().get("USER_INFO");
        if (profile == null) return Collections.emptyList();

        JsonNode value = AbstractJsonUserAttributeMapper.getJsonValue(profile, claim);
        if (value == null || value.isNull()) return Collections.emptyList();

        List<String> result = new ArrayList<>();
        if (value.isArray()) {
            for (JsonNode node : value) {
                if (node.isTextual()) result.add(node.asText());
            }
        } else if (value.isTextual()) {
            result.add(value.asText());
        }
        return result;
    }
}
