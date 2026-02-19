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
        this.syncGroups(realm, user, mapperModel, context);
    }
    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        this.syncGroups(realm, user, mapperModel, context);
    }
    public static List<String> getClaimValue(BrokeredIdentityContext context, String claim) {
        JsonNode profileJsonNode = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        var roles = AbstractJsonUserAttributeMapper.getJsonValue(profileJsonNode, claim);
        if(roles == null) {
            return new ArrayList<>();
        }
        // convert to string list if not list
        List<String> newList = new ArrayList<>();
        if (!List.class.isAssignableFrom(roles.getClass())) {
            newList.add(roles.toString());
        }
        else {
            newList = (List<String>)roles;
        }
        return newList;
    }
    private void syncGroups(RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.info("=== DEBUG SYNC START ===");
        logger.info("=== DEBUG createGroups: " + mapperModel.getConfig().get(CREATE_GROUPS));

        boolean createGroups = Boolean.parseBoolean(mapperModel.getConfig().get(CREATE_GROUPS));
        if (!createGroups) {
            logger.info("=== DEBUG createGroups is false, exiting ===");
            return;
        }

        JsonNode userInfo = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        logger.info("=== DEBUG userInfo present: " + (userInfo != null));

        if (userInfo != null) {
            logger.info("=== DEBUG userInfo JSON: " + userInfo.toPrettyString());
            logger.info("=== DEBUG userInfo guilds node type: " + userInfo.path("guilds").getNodeType());
            logger.info("=== DEBUG userInfo guilds is array: " + userInfo.path("guilds").isArray());
            logger.info("=== DEBUG userInfo guilds size: " + userInfo.path("guilds").size());
        } else {
            logger.info("=== DEBUG userInfo is null ===");
            logger.info("=== DEBUG contextData keys: " + context.getContextData().keySet());
        }

        JsonNode guildsNode = userInfo != null ? userInfo.path("guilds") : null;
        if (guildsNode == null || !guildsNode.isArray() || guildsNode.size() == 0) {
            logger.info("=== DEBUG no valid guilds array found, exiting ===");
            return;
        }

        Set<GroupModel> currentGroups = user.getGroupsStream().collect(Collectors.toSet());
        Set<GroupModel> newGroups = new HashSet<>();

        for (JsonNode guild : guildsNode) {
            JsonNode rolesNode = guild.path("roles");
            if (!rolesNode.isArray()) continue;

            for (JsonNode roleNode : rolesNode) {
                String roleId = roleNode.asText(null);
                if (roleId == null) continue;

                String groupName = "DiscordRole-" + roleId;

                GroupModel group = getGroupByName(realm, groupName);
                boolean newlyCreated = false;

                if (group == null) {
                    group = realm.createGroup(groupName);
                    newlyCreated = true;
                    logger.info("=== DEBUG Created group: " + groupName + " for role: " + roleId);
                }

                if (newlyCreated) {
                    group.setSingleAttribute("discord_role_id", roleId);
                    logger.info("=== DEBUG Set attribute discord_role_id = " + roleId + " on group " + groupName);
                }

                newGroups.add(group);
            }
        }

        Set<GroupModel> removeGroups = getGroupsToBeRemoved(currentGroups, newGroups);
        for (GroupModel group : removeGroups)
            user.leaveGroup(group);

        Set<GroupModel> addGroups = getGroupsToBeAdded(currentGroups, newGroups);
        for (GroupModel group : addGroups)
            user.joinGroup(group);

        logger.info("=== DEBUG SYNC FINISH ===");
    }
    private static GroupModel getGroupByName(RealmModel realm, String name) {
        Optional<GroupModel> group = realm.getGroupsStream()
                .filter(g -> g.getName().equals(name))
                .findFirst();
        return group.orElse(null);
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
