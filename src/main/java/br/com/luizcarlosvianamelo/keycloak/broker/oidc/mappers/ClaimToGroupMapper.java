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
import org.keycloak.util.JsonSerialization;

/**
 * Class with the implementation of the identity provider mapper that sync the
 * user's groups received from an external IdP into the Keycloak groups.
 *
 * @author Luiz Carlos Viana Melo
 */
public class ClaimToGroupMapper extends AbstractClaimMapper {
    // logger ------------------------------------------------
    private static final Logger logger = Logger.getLogger(ClaimToGroupMapper.class);
    // global properties -------------------------------------
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
    // properties --------------------------------------------
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
    // actions -----------------------------------------------
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
        List<String> newGroupsList = getClaimValue(context, groupClaimName);
        boolean clearRolesIfNone = Boolean.parseBoolean(mapperModel.getConfig().get(CLEAR_ROLES_IF_NONE));
        if (newGroupsList.isEmpty() && !clearRolesIfNone) {
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
        Set<String> effectiveGroupNames = new HashSet<>(newGroupsList
                .stream()
                .filter(t -> isEmpty(containsText) || t.contains(containsText))
                .collect(Collectors.toSet()));
        String accessToken = null;
        FederatedIdentityModel fedIdentity = session.users().getFederatedIdentity(realm, user, mapperModel.getIdentityProviderAlias());
        if (fedIdentity != null && fedIdentity.getToken() != null) {
            try {
                accessToken = fedIdentity.getToken();
                logger.debugf("Retrieved external access token from FederatedIdentityModel for user %s", user.getUsername());
            } catch (Exception e) {
                logger.warnf("Failed to retrieve stored token for user %s: %s", user.getUsername(), e.getMessage());
            }
        }
        if (accessToken != null && !discordMappings.isEmpty()) {
            for (MappingEntry entry : discordMappings) {
                try {
                    String url = "https://discord.com/api/v10/users/@me/guilds/" + entry.guildId + "/member";
                    JsonNode member = SimpleHttp.doGet(url, session)
                            .header("Authorization", "Bearer " + accessToken)
                            .asJson();
                    if (member != null && !member.isMissingNode()) {
                        boolean hasAccess = false;
                        if (entry.roleId.isEmpty()) {
                            hasAccess = true;
                        } else {
                            JsonNode rolesNode = member.get("roles");
                            if (rolesNode != null && rolesNode.isArray()) {
                                for (JsonNode role : rolesNode) {
                                    if (entry.roleId.equals(role.asText())) {
                                        hasAccess = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (hasAccess) {
                            effectiveGroupNames.add(entry.groupName);
                            logger.debugf("Added group from Discord API: %s (guild=%s, role=%s)", entry.groupName, entry.guildId, entry.roleId.isEmpty() ? "membership" : entry.roleId);
                        }
                    }
                } catch (Exception e) {
                    logger.warnf("Failed to check Discord membership for guild %s: %s", entry.guildId, e.getMessage());
                }
            }
        }
        Set<GroupModel> currentGroups = user.getGroupsStream()
                .filter(g -> isEmpty(containsText) || g.getName().contains(containsText))
                .collect(Collectors.toSet());
        Set<GroupModel> newGroups = getNewGroups(session, realm, effectiveGroupNames, createGroups, discordMappings);
        Set<GroupModel> removeGroups = getGroupsToBeRemoved(currentGroups, newGroups);
        for (GroupModel group : removeGroups)
            user.leaveGroup(group);
        Set<GroupModel> addGroups = getGroupsToBeAdded(currentGroups, newGroups);
        for (GroupModel group : addGroups)
            user.joinGroup(group);
        logger.debugf("Realm [%s], IdP [%s]: finishing mapping groups for user [%s]",
                realm.getName(),
                mapperModel.getIdentityProviderAlias(),
                user.getUsername());
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
