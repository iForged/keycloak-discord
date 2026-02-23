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

/**
 * Class with the implementation of the identity provider mapper that sync the
 * user's groups received from an external IdP into the Keycloak groups.
 *
 * @author Luiz Carlos Viana Melo
 */
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
    private static final String CLEAR_GROUPS_IF_NONE = "clearGroupsIfNone";

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
        property.setDefaultValue(Boolean.TRUE.toString());
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLEAR_GROUPS_IF_NONE);
        property.setLabel("Clear groups if no groups found");
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
        return "Claim to Group Mapper (Discord compatible)";
    }

    @Override
    public String getHelpText() {
        return "Синхронизирует группы из IdP claim в группы realm.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        super.importNewUser(session, realm, user, mapperModel, context);
        syncGroups(realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        syncGroups(realm, user, mapperModel, context);
    }

    public static List<String> getClaimValue(BrokeredIdentityContext context, String claim) {
        JsonNode profileJsonNode = (JsonNode) context.getContextData().get(AbstractJsonUserAttributeMapper.USER_INFO);
        if (profileJsonNode == null) {
            logger.warn("USER_INFO not found in context");
            return Collections.emptyList();
        }

        Object value = AbstractJsonUserAttributeMapper.getJsonValue(profileJsonNode, claim);
        if (value == null) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        if (value instanceof List) {
            for (Object item : (List<?>) value) {
                result.add(item.toString());
            }
        } else if (value instanceof JsonNode node && node.isArray()) {
            for (JsonNode n : node) {
                result.add(n.asText());
            }
        } else {
            result.add(value.toString());
        }
        return result;
    }

    private void syncGroups(RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claimName = mapperModel.getConfig().get(CLAIM);
        if (isEmpty(claimName)) {
            return;
        }

        String containsText = mapperModel.getConfig().get(CONTAINS_TEXT);
        boolean createGroups = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(CREATE_GROUPS, "true"));
        boolean clearIfNone = Boolean.parseBoolean(mapperModel.getConfig().get(CLEAR_GROUPS_IF_NONE));

        List<String> newGroupsList = getClaimValue(context, claimName);

        if (newGroupsList.isEmpty() && !clearIfNone) {
            logger.debugf("No groups in claim '%s' for user %s → ignoring", claimName, user.getUsername());
            return;
        }

        logger.debugf("Syncing groups for user %s from claim '%s': %s", user.getUsername(), claimName, newGroupsList);

        Set<String> desiredNames = newGroupsList.stream()
                .filter(name -> isEmpty(containsText) || name.contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> current = user.getGroupsStream()
                .filter(g -> isEmpty(containsText) || g.getName().contains(containsText))
                .collect(Collectors.toSet());

        Set<GroupModel> target = getOrCreateGroups(realm, desiredNames, createGroups);

        Set<GroupModel> toRemove = new HashSet<>(current);
        toRemove.removeAll(target);

        Set<GroupModel> toAdd = new HashSet<>(target);
        toAdd.removeAll(current);

        toRemove.forEach(user::leaveGroup);
        toAdd.forEach(user::joinGroup);

        logger.debugf("Sync finished: added %d, removed %d for user %s", toAdd.size(), toRemove.size(), user.getUsername());
    }

    private Set<GroupModel> getOrCreateGroups(RealmModel realm, Set<String> names, boolean create) {
        Set<GroupModel> groups = new HashSet<>();
        for (String name : names) {
            GroupModel group = realm.getGroupByName(name);
            if (group == null && create) {
                logger.debugf("Creating missing group: %s", name);
                group = realm.createGroup(name);
            }
            if (group != null) {
                groups.add(group);
            }
        }
        return groups;
    }

    private static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }
}
