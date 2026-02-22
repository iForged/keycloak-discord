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

        Set<GroupModel> currentGroups = user.getGroupsStream()
                .filter(g -> isEmpty(containsText) || g.getName().contains(containsText))
                .collect(Collectors.toSet());

        logger.debugf("Realm [%s], IdP [%s]: current groups for user [%s]: %s",
                realm.getName(),
                mapperModel.getIdentityProviderAlias(),
                user.getUsername(),
                currentGroups
                        .stream()
                        .map(GroupModel::getName)
                        .collect(Collectors.joining(","))
        );

        @SuppressWarnings("unchecked")
        Set<String> newGroupsNames = newGroupsList
                .stream()
                .filter(t -> isEmpty(containsText) || t.contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> newGroups = getNewGroups(realm, newGroupsNames, createGroups);

        logger.debugf("Realm [%s], IdP [%s]: new groups for user [%s]: %s",
                realm.getName(),
                mapperModel.getIdentityProviderAlias(),
                user.getUsername(),
                newGroups
                        .stream()
                        .map(GroupModel::getName)
                        .collect(Collectors.joining(","))
        );

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

    private Set<GroupModel> getNewGroups(RealmModel realm, Set<String> newGroupsNames, boolean createGroups) {

        Set<GroupModel> groups = new HashSet<>();

        for (String groupName : newGroupsNames) {
            GroupModel group = getGroupByName(realm, groupName);

            if (group == null && createGroups) {
                logger.debugf("Realm [%s]: creating group [%s]",
                        realm.getName(),
                        groupName);

                group = realm.createGroup(groupName);
            }

            if (group != null)
                groups.add(group);
        }

        return groups;
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
