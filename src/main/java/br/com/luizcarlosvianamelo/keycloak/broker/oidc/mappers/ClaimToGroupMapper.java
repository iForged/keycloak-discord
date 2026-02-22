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
    private static final String DISCORD_ROLE_MAPPING = "discord_role_mapping";

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(CLAIM);
        property.setLabel("Claim");
        property.setHelpText("Name of claim to search for in token. This claim must be a string array with the names of the groups which the user is member. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CONTAINS_TEXT);
        property.setLabel("Contains text");
        property.setHelpText("Only sync groups that contains this text in its name. If empty, sync all groups.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CREATE_GROUPS);
        property.setLabel("Create groups if not exists");
        property.setHelpText("Indicates if missing groups must be created in the realms. Otherwise, they will be ignored.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLEAR_ROLES_IF_NONE);
        property.setLabel("Clear groups if no groups found");
        property.setHelpText("Should previously assigned groups be cleared if no groups can be retrieved");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(DISCORD_ROLE_MAPPING);
        property.setLabel("Discord Role Mapping");
        property.setHelpText("Multiline mapping of Discord roles → Keycloak groups\n" +
                             "Format: guild_id:role_id:group_name\n" +
                             "Examples:\n" +
                             "1307843121031282738:1308020497815965727:DiscordAdmin\n" +
                             "1307843121031282738:1308020875131486208:Test\n" +
                             "1307843121031282738::GuildMember   ← guild membership without a role\n" +
                             "\nLines starting with # are ignored\nEmpty lines are ignored");
        property.setType(ProviderConfigProperty.TEXT_TYPE);
        CONFIG_PROPERTIES.add(property);
    }

    private static class MappingEntry {
        String guildId;
        String roleId;
        String groupName;

        MappingEntry(String guildId, String roleId, String groupName) {
            this.guildId = guildId;
            this.roleId = roleId;
            this.groupName = groupName;
        }
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
        return "Sync groups from claim or Discord roles mapping to realm groups";
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
        if (profile == null) {
            return Collections.emptyList();
        }

        JsonNode value = AbstractJsonUserAttributeMapper.getJsonValue(profile, claim);
        if (value == null || value.isNull()) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        if (value.isArray()) {
            for (JsonNode node : value) {
                if (node.isTextual()) {
                    result.add(node.asText());
                }
            }
        } else if (value.isTextual()) {
            result.add(value.asText());
        }
        return result;
    }
}
