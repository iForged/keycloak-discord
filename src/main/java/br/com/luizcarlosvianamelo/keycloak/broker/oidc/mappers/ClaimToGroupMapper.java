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
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.FederatedIdentityModel;

public class ClaimToGroupMapper extends AbstractClaimMapper {

    private static final Logger logger = Logger.getLogger(ClaimToGroupMapper.class);

    private static final String PROVIDER_ID = "oidc-group-idp-mapper";
    private static final String[] COMPATIBLE_PROVIDERS = {
            KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            OIDCIdentityProviderFactory.PROVIDER_ID,
            DiscordIdentityProviderFactory.PROVIDER_ID
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();
    private static final String CONTAINS_TEXT = "contains_text";
    private static final String CREATE_GROUPS = "create_groups";
    private static final String CLEAR_ROLES_IF_NONE = "clearRolesIfNone";
    private static final String DISCORD_ROLE_MAPPING = "discord_role_mapping";
    private static final String DISCORD_BOT_TOKEN = "discord_bot_token";

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(CLAIM);
        property.setLabel("Claim");
        property.setHelpText("Name of claim to search for in token.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CONTAINS_TEXT);
        property.setLabel("Contains text");
        property.setHelpText("Only sync groups that contains this text in its name.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CREATE_GROUPS);
        property.setLabel("Create groups if not exists");
        property.setHelpText("Indicates if missing groups must be created in the realms.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLEAR_ROLES_IF_NONE);
        property.setLabel("Clear discord roles if no roles found");
        property.setHelpText("Should Discord roles be cleared out if no roles can be retrieved");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(DISCORD_ROLE_MAPPING);
        property.setLabel("Discord Role Mapping");
        property.setHelpText("Format: <guild_id>:<role_id>:<group_name>");
        property.setType(ProviderConfigProperty.TEXT_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(DISCORD_BOT_TOKEN);
        property.setLabel("Discord Bot Token");
        property.setType(ProviderConfigProperty.PASSWORD);
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
        return "If a claim exists, sync the IdP user's groups with realm groups";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        super.importNewUser(session, realm, user, mapperModel, context);
        this.syncGroups(session, realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        this.syncGroups(session, realm, user, mapperModel, context);
    }

    public static List<String> getClaimValue(BrokeredIdentityContext context, String claim) {
        JsonNode profileJsonNode = (JsonNode) context.getContextData().get("USER_INFO");
        var roles = AbstractJsonUserAttributeMapper.getJsonValue(profileJsonNode, claim);
        if (roles == null) {
            return new ArrayList<>();
        }
        if (roles instanceof List) {
            return (List<String>) roles;
        }
        return List.of(roles.toString());
    }

    private List<MappingEntry> getDiscordRoleMapping(IdentityProviderMapperModel mapperModel) {
        String configValue = mapperModel.getConfig().get(DISCORD_ROLE_MAPPING);
        if (configValue == null || configValue.trim().isEmpty()) {
            return Collections.emptyList();
        }
        List<MappingEntry> mappings = new ArrayList<>();
        String[] lines = configValue.split("\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split(":", -1);
            if (parts.length != 3) continue;
            mappings.add(new MappingEntry(parts[0].trim(), parts[1].trim(), parts[2].trim()));
        }
        return mappings;
    }

    private void syncGroups(KeycloakSession session, RealmModel realm, UserModel user,
                            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        String groupClaimName = mapperModel.getConfig().get(CLAIM);
        String containsText = mapperModel.getConfig().get(CONTAINS_TEXT);
        boolean createGroups = Boolean.parseBoolean(mapperModel.getConfig().get(CREATE_GROUPS));
        boolean clearRolesIfNone = Boolean.parseBoolean(mapperModel.getConfig().get(CLEAR_ROLES_IF_NONE));
        String botToken = mapperModel.getConfig().get(DISCORD_BOT_TOKEN);

        if (isEmpty(groupClaimName)) return;

        List<String> newGroupsList = getClaimValue(context, groupClaimName);

        if (newGroupsList.isEmpty() && !clearRolesIfNone) return;

        List<MappingEntry> discordMappings = getDiscordRoleMapping(mapperModel);

        Set<String> effectiveGroupNames = new HashSet<>(newGroupsList
                .stream()
                .filter(t -> isEmpty(containsText) || t.contains(containsText))
                .collect(Collectors.toSet()));

        if (botToken != null && !botToken.isEmpty() && !discordMappings.isEmpty()) {
            for (MappingEntry entry : discordMappings) {
                try {
                    String url = "https://discord.com/api/v10/guilds/" + entry.guildId + "/members/" + context.getUsername();

                    JsonNode member = SimpleHttp.doGet(url, session)
                            .header("Authorization", "Bot " + botToken)
                            .asJson();

                    logger.infof("Discord member JSON: %s", member != null ? member.toString() : "null");

                    if (member != null) {
                        JsonNode rolesNode = member.get("roles");
                        boolean hasAccess = false;

                        if (entry.roleId.isEmpty()) {
                            hasAccess = true;
                        } else if (rolesNode != null && rolesNode.isArray()) {
                            for (JsonNode role : rolesNode) {
                                if (entry.roleId.equals(role.asText())) {
                                    hasAccess = true;
                                    break;
                                }
                            }
                        }

                        if (hasAccess) {
                            effectiveGroupNames.add(entry.groupName);
                        }
                    }

                } catch (Exception e) {
                    logger.errorf(e, "Exception during Discord API check for guild %s", entry.guildId);
                }
            }
        }

        Set<GroupModel> currentGroups = user.getGroupsStream()
                .filter(g -> isEmpty(containsText) || g.getName().contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> newGroups = getNewGroups(session, realm, effectiveGroupNames, createGroups, discordMappings);
        Set<GroupModel> removeGroups = getGroupsToBeRemoved(currentGroups, newGroups);
        Set<GroupModel> addGroups = getGroupsToBeAdded(currentGroups, newGroups);

        for (GroupModel group : removeGroups) user.leaveGroup(group);
        for (GroupModel group : addGroups) user.joinGroup(group);
    }

    private Set<GroupModel> getNewGroups(KeycloakSession session, RealmModel realm,
                                         Set<String> newGroupsNames, boolean createGroups,
                                         List<MappingEntry> discordMappings) {

        Set<GroupModel> groups = new HashSet<>();
        Map<String, MappingEntry> mappingByGroup = discordMappings.stream()
                .collect(Collectors.toMap(e -> e.groupName, e -> e));

        for (String groupName : newGroupsNames) {
            GroupModel group = session.groups().getGroupByName(realm, null, groupName);
            boolean newlyCreated = false;

            if (group == null && createGroups) {
                group = session.groups().createGroup(realm, groupName);
                newlyCreated = true;
            }

            if (group != null) {
                MappingEntry entry = mappingByGroup.get(groupName);
                if (newlyCreated && entry != null && entry.roleId != null && !entry.roleId.isEmpty()) {
                    group.setSingleAttribute("discord_role_id", entry.roleId);
                }
                groups.add(group);
            }
        }
        return groups;
    }

    private static Set<GroupModel> getGroupsToBeRemoved(Set<GroupModel> currentGroups, Set<GroupModel> newGroups) {
        Set<GroupModel> resultSet = new HashSet<>(currentGroups);
        resultSet.removeAll(newGroups);
        return resultSet;
    }

    private static Set<GroupModel> getGroupsToBeAdded(Set<GroupModel> currentGroups, Set<GroupModel> newGroups) {
        Set<GroupModel> resultSet = new HashSet<>(newGroups);
        resultSet.removeAll(currentGroups);
        return resultSet;
    }

    private static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }
}
