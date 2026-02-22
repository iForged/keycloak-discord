package br.com.luizcarlosvianamelo.keycloak.broker.oidc.mappers;

import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
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

/**
 * Class with the implementation of the identity provider mapper that sync the
 * user's groups received from an external IdP into the Keycloak groups.
 *
 * @author Luiz Carlos Viana Melo
 */
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
        property.setHelpText("Name of claim to search for in token. This claim must be a string array with " +
                "the names of the groups which the user is member. You can reference nested claims using a " +
                "'.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)");
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
        property.setHelpText("Indicates if missing groups must be created in the realms. Otherwise, they will " +
                "be ignored.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLEAR_ROLES_IF_NONE);
        property.setLabel("Clear discord roles if no roles found");
        property.setHelpText("Should Discord roles be cleared out if no roles can be retrieved for example when a user is no longer part of the discord server");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(DISCORD_ROLE_MAPPING);
        property.setLabel("Discord Role Mapping");
        property.setHelpText("Map Discord roles to Keycloak groups. Format: <guild_id>:<role_id>:<group_name_in_keycloak> or <guild_id>::<group_name> (for membership in guild without specific role). Use comma as separator for multiple mappings. Example: 123456789:987654321:Moderators,111222333::Members");
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
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        super.importNewUser(session, realm, user, mapperModel, context);
        this.syncGroups(session, realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        this.syncGroups(session, realm, user, mapperModel, context);
    }

    public static List<String> getClaimValue(BrokeredIdentityContext context, String claim) {
        JsonNode profileJsonNode = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        var roles = AbstractJsonUserAttributeMapper.getJsonValue(profileJsonNode, claim);
        if(roles == null) {
            return new ArrayList<>();
        }
        List<String> newList = new ArrayList<>();
        if (!List.class.isAssignableFrom(roles.getClass())) {
            newList.add(roles.toString());
        }
        else {
            newList = (List<String>)roles;
        }
        return newList;
    }

    private List<MappingEntry> getDiscordRoleMapping(IdentityProviderMapperModel mapperModel) {
        String configValue = mapperModel.getConfig().get(DISCORD_ROLE_MAPPING);
        if (configValue == null || configValue.trim().isEmpty()) {
            logger.debug("No Discord Role Mapping configured in mapper");
            return Collections.emptyList();
        }
        List<MappingEntry> mappings = new ArrayList<>();
        String[] lines = configValue.split("\\r?\\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(":", -1);
            if (parts.length != 3) {
                logger.warnf("Invalid mapping entry (expected 3 parts): %s", line);
                continue;
            }
            String guildId = parts[0].trim();
            String roleId = parts[1].trim();
            String groupName = parts[2].trim();
            if (groupName.isEmpty() || guildId.isEmpty()) {
                logger.warnf("Invalid mapping entry - empty group or guild: %s", line);
                continue;
            }
            mappings.add(new MappingEntry(guildId, roleId, groupName));
            logger.debugf("Loaded mapping: group=%s → roleId=%s (guild=%s)", groupName, roleId, guildId);
        }
        return mappings;
    }

    private void syncGroups(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String groupClaimName = mapperModel.getConfig().get(CLAIM);
        String containsText = mapperModel.getConfig().get(CONTAINS_TEXT);
        boolean createGroups = Boolean.parseBoolean(mapperModel.getConfig().get(CREATE_GROUPS));
        if (isEmpty(groupClaimName))
            return;

        List<String> claimGroups = getClaimValue(context, groupClaimName);

        boolean clearRolesIfNone = Boolean.parseBoolean(mapperModel.getConfig().get(CLEAR_ROLES_IF_NONE));
        if (claimGroups.isEmpty() && !clearRolesIfNone) {
            logger.debugf("Realm [%s], IdP [%s]: no group claim (claim name: [%s]) for user [%s], ignoring...",
                    realm.getName(),
                    mapperModel.getIdentityProviderAlias(),
                    groupClaimName,
                    user.getUsername());
            return;
        }

        logger.debugf("Realm [%s], IdP [%s]: starting mapping groups for user [%s]",
                realm.getName(),
                mapperModel.getIdentityProviderAlias(),
                user.getUsername());

        List<MappingEntry> discordMappings = getDiscordRoleMapping(mapperModel);

        logger.infof("Loaded %d Discord mappings", discordMappings.size());

        if (!discordMappings.isEmpty() && createGroups) {
            Map<String, MappingEntry> mappingByGroup = discordMappings.stream()
                    .collect(Collectors.toMap(e -> e.groupName, e -> e, (o, n) -> n));

            for (MappingEntry entry : mappingByGroup.values()) {
                GroupModel group = session.groups().getGroupByName(realm, null, entry.groupName);
                if (group == null) {
                    logger.debugf("Realm [%s]: creating group [%s] from discord mapping", realm.getName(), entry.groupName);
                    group = session.groups().createGroup(realm, entry.groupName);
                    if (!entry.roleId.isEmpty()) {
                        group.setSingleAttribute("discord_role_id", entry.roleId);
                        logger.infof("Created group [%s] and set discord_role_id = [%s]", entry.groupName, entry.roleId);
                    }
                } else {
                    logger.debugf("Group [%s] already exists", entry.groupName);
                }
            }
        }

        Set<String> discordGrantedGroups = new HashSet<>();
        if (!discordMappings.isEmpty()) {
            String accessToken = (String) context.getContextData().get("ACCESS_TOKEN");
            if (accessToken == null) {
                accessToken = (String) context.getContextData().get("access_token");
            }

            if (accessToken != null && !accessToken.isEmpty()) {
                logger.infof("Using user access token for Discord role checks");
                for (MappingEntry entry : discordMappings) {
                    try {
                        String url = "https://discord.com/api/v10/users/@me/guilds/" + entry.guildId + "/member";
                        logger.infof("Requesting Discord member info for guild %s", entry.guildId);

                        JsonNode member = SimpleHttp.doGet(url, session)
                                .header("Authorization", "Bearer " + accessToken)
                                .asJson();

                        if (member == null || member.has("message")) {
                            logger.warnf("Discord API error for guild %s: %s", entry.guildId, member != null ? member.toString() : "null");
                            continue;
                        }

                        JsonNode rolesNode = member.get("roles");
                        if (rolesNode == null || !rolesNode.isArray()) {
                            logger.warnf("No roles array in response for guild %s", entry.guildId);
                            continue;
                        }

                        boolean hasAccess = entry.roleId.isEmpty();
                        if (!hasAccess) {
                            for (JsonNode role : rolesNode) {
                                String roleStr = role.asText();
                                if (entry.roleId.equals(roleStr)) {
                                    hasAccess = true;
                                    break;
                                }
                            }
                        }

                        if (hasAccess) {
                            discordGrantedGroups.add(entry.groupName);
                            logger.debugf("Added group from Discord API: %s (guild=%s, role=%s)", entry.groupName, entry.guildId, entry.roleId.isEmpty() ? "membership" : entry.roleId);
                        }
                    } catch (Exception e) {
                        logger.errorf(e, "Exception during Discord API check for guild %s", entry.guildId);
                    }
                }
            } else {
                logger.infof("No access token found in context - skipping Discord role check");
            }
        }

        Set<String> effectiveGroupNames = new HashSet<>();

        Set<String> filteredClaimGroups = claimGroups.stream()
                .filter(t -> isEmpty(containsText) || t.contains(containsText))
                .collect(Collectors.toSet());
        effectiveGroupNames.addAll(filteredClaimGroups);
        logger.infof("Claim groups for user [%s] (after filter): %s",
                user.getUsername(),
                String.join(", ", filteredClaimGroups));

        Set<String> filteredDiscordGroups = discordGrantedGroups.stream()
                .filter(t -> isEmpty(containsText) || t.contains(containsText))
                .collect(Collectors.toSet());
        effectiveGroupNames.addAll(filteredDiscordGroups);
        logger.infof("Discord granted groups for user [%s] (after filter): %s",
                user.getUsername(),
                String.join(", ", filteredDiscordGroups));

        logger.infof("Effective group names for user [%s]: %s",
                user.getUsername(),
                String.join(", ", effectiveGroupNames));

        Set<GroupModel> currentGroups = user.getGroupsStream()
                .filter(g -> isEmpty(containsText) || g.getName().contains(containsText))
                .collect(Collectors.toSet());
        logger.infof("Current groups for user [%s]: %s",
                user.getUsername(),
                currentGroups.stream().map(GroupModel::getName).collect(Collectors.joining(", ")));

        logger.infof("Will try to assign these groups: %s",
                String.join(", ", effectiveGroupNames));
        Set<GroupModel> newGroups = getNewGroups(session, realm, effectiveGroupNames, createGroups, discordMappings);
        logger.infof("Final target groups (after getNewGroups): %s",
                newGroups.stream().map(GroupModel::getName).collect(Collectors.joining(", ")));

        Set<GroupModel> removeGroups = getGroupsToBeRemoved(currentGroups, newGroups);
        Set<GroupModel> addGroups = getGroupsToBeAdded(currentGroups, newGroups);

        logger.infof("Groups to ADD for user [%s]: %s",
                user.getUsername(),
                addGroups.stream().map(GroupModel::getName).collect(Collectors.joining(", ")));
        logger.infof("Groups to REMOVE for user [%s]: %s",
                user.getUsername(),
                removeGroups.stream().map(GroupModel::getName).collect(Collectors.joining(", ")));

        for (GroupModel group : removeGroups) {
            user.leaveGroup(group);
            logger.debugf("User [%s] left group [%s]", user.getUsername(), group.getName());
        }

        for (GroupModel group : addGroups) {
            user.joinGroup(group);
            logger.debugf("User [%s] joined group [%s]", user.getUsername(), group.getName());
        }

        logger.debugf("Realm [%s], IdP [%s]: finishing mapping groups for user [%s] (final groups: %d)",
                realm.getName(),
                mapperModel.getIdentityProviderAlias(),
                user.getUsername(),
                user.getGroupsStream().count());
    }

    private Set<GroupModel> getNewGroups(KeycloakSession session, RealmModel realm, Set<String> newGroupsNames, boolean createGroups, List<MappingEntry> discordMappings) {
        Set<GroupModel> groups = new HashSet<>();
        Map<String, MappingEntry> mappingByGroup = discordMappings.stream()
                .collect(Collectors.toMap(e -> e.groupName, e -> e));

        for (String groupName : newGroupsNames) {
            GroupModel group = session.groups().getGroupByName(realm, null, groupName);
            boolean newlyCreated = false;

            if (group == null && createGroups) {
                logger.debugf("Realm [%s]: creating group [%s]", realm.getName(), groupName);
                group = session.groups().createGroup(realm, groupName);
                newlyCreated = true;
            }

            if (group != null) {
                MappingEntry entry = mappingByGroup.get(groupName);
                String roleId = entry != null ? entry.roleId : null;
                String current = group.getFirstAttribute("discord_role_id");

                if (newlyCreated) {
                    if (roleId != null && !roleId.isEmpty()) {
                        group.setSingleAttribute("discord_role_id", roleId);
                        logger.infof("Created group [%s] and set discord_role_id = [%s]", groupName, roleId);
                    } else {
                        logger.warnf("Created group [%s] but no roleId found in mapping for this group", groupName);
                    }
                } else if (current != null && !current.isEmpty()) {
                    logger.debugf("Group [%s] already has discord_role_id = %s", groupName, current);
                }

                groups.add(group);
            } else {
                logger.warnf("Group [%s] not found and not created (createGroups=%b)", groupName, createGroups);
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
