package ca.ibodrov.concord.oidc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class KeycloakContainer extends GenericContainer<KeycloakContainer> {

    private static final TypeReference<List<Map<String, Object>>> LIST_OF_JSON_OBJECTS = new TypeReference<List<Map<String, Object>>>() {
    };

    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:25.0.6";
    private static final int KEYCLOAK_PORT = 8080;

    private static final String KEYCLOAK_ADMIN_USER = "admin";
    private static final String KEYCLOAK_ADMIN_PASSWORD = "admin";

    private String realmName = "test-realm";
    private String clientId = "test-client";
    private String clientSecret = "test-secret";
    private List<String> redirectUris;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public KeycloakContainer() {
        super(KEYCLOAK_IMAGE);
        withExposedPorts(KEYCLOAK_PORT);
        withEnv("KEYCLOAK_ADMIN", KEYCLOAK_ADMIN_USER);
        withEnv("KEYCLOAK_ADMIN_PASSWORD", KEYCLOAK_ADMIN_PASSWORD);
        withCommand(
                "start-dev",
                "--http-port=" + KEYCLOAK_PORT,
                "--hostname=localhost",
                "--features=preview");
        waitingFor(Wait.forHttp("/")
                .forPort(KEYCLOAK_PORT)
                .withStartupTimeout(Duration.ofMinutes(5)));

        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public String getRealmName() {
        return realmName;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getDiscoveryUrl() {
        if (!isRunning()) {
            throw new RuntimeException("The keycloak container must be running first.");
        }

        return String.format("http://%s:%d/realms/%s/.well-known/openid-configuration", getHost(),
                getMappedPort(KEYCLOAK_PORT), realmName);
    }

    public String getAuthorizationUrl() {
        if (!isRunning()) {
            throw new RuntimeException("The keycloak container must be running first.");
        }

        return String.format("http://%s:%d/realms/%s/protocol/openid-connect/auth",
                getHost(), getMappedPort(KEYCLOAK_PORT), realmName);
    }

    public String getTokenUrl() {
        if (!isRunning()) {
            throw new RuntimeException("The keycloak container must be running first.");
        }

        return String.format("http://%s:%d/realms/%s/protocol/openid-connect/token",
                getHost(), getMappedPort(KEYCLOAK_PORT), realmName);
    }

    public String getUserInfoUrl() {
        if (!isRunning()) {
            throw new RuntimeException("The keycloak container must be running first.");
        }

        return String.format("http://%s:%d/realms/%s/protocol/openid-connect/userinfo",
                getHost(), getMappedPort(KEYCLOAK_PORT), realmName);
    }

    public String getLogOutUrl() {
        if (!isRunning()) {
            throw new RuntimeException("The keycloak container must be running first.");
        }

        return String.format("http://%s:%d/realms/%s/protocol/openid-connect/logout",
                getHost(), getMappedPort(KEYCLOAK_PORT), realmName);
    }

    public KeycloakContainer withRealmName(String realmName) {
        this.realmName = realmName;
        return this;
    }

    public KeycloakContainer withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public KeycloakContainer withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public KeycloakContainer withRedirectUris(String... redirectUris) {
        this.redirectUris = Arrays.asList(redirectUris);
        return this;
    }

    @Override
    public void start() {
        super.start();
        try {
            var accessToken = getAdminAccessToken();
            createRealm(accessToken);
            createClient(accessToken);
            createTestUsers(accessToken);
            createRequiredScopes(accessToken);
            assignScopesToClient(accessToken);
            createGroups(accessToken);
            assignUsersToGroups(accessToken);
            createGroupsMapper(accessToken);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to initialize Keycloak", e);
        }
    }

    private void createRequiredScopes(String accessToken) throws IOException, InterruptedException {
        var requiredScopes = Arrays.asList("openid", "profile", "email", "groups");
        for (var scope : requiredScopes) {
            if (scopeExists(accessToken, scope)) {
                continue;
            }
            createScope(accessToken, scope);
        }

        configureGroupsScope(accessToken);
    }

    private void configureGroupsScope(String accessToken) throws IOException, InterruptedException {
        var groupsScopeId = getClientScopeId(accessToken, "groups");
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/client-scopes/" + groupsScopeId;

        var groupsScopeConfig = Map.of(
                "name", "groups",
                "protocol", "openid-connect",
                "protocolMappers", List.of(Map.of(
                        "name", "groups",
                        "protocol", "openid-connect",
                        "protocolMapper", "oidc-usermodel-realm-role-mapper",
                        "consentRequired", false,
                        "config", Map.of(
                                "multivalued", "true",
                                "user.attribute", "foo",
                                "id.token.claim", "true",
                                "access.token.claim", "true",
                                "claim.name", "groups",
                                "jsonType.label", "String"))));

        putJson(endpoint, accessToken, groupsScopeConfig);
    }

    private void createGroupsMapper(String accessToken) throws IOException, InterruptedException {
        var clientId = getClientId(accessToken);
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/clients/" + clientId
                + "/protocol-mappers/models";

        var groupsMapper = Map.of(
                "name", "groups",
                "protocol", "openid-connect",
                "protocolMapper", "oidc-group-membership-mapper",
                "consentRequired", false,
                "config", Map.of(
                        "full.path", false,
                        "id.token.claim", true,
                        "access.token.claim", true,
                        "claim.name", "groups",
                        "userinfo.token.claim", true));

        postJson(endpoint, accessToken, groupsMapper);
    }

    private boolean scopeExists(String accessToken, String scopeName) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/client-scopes";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var scopes = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        return scopes.stream().anyMatch(scope -> scope.get("name").equals(scopeName));
    }

    private void createScope(String accessToken, String scopeName) throws IOException, InterruptedException {
        var clientScopesEndpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/client-scopes";
        var scope = Map.of("name", scopeName, "protocol", "openid-connect");
        postJson(clientScopesEndpoint, accessToken, scope);
    }

    private void assignScopesToClient(String accessToken) throws IOException, InterruptedException {
        var clientId = getClientId(accessToken);
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/clients/" + clientId
                + "/default-client-scopes/";

        for (var scope : Arrays.asList("openid", "profile", "email", "groups")) {
            var scopeId = getClientScopeId(accessToken, scope);
            var request = buildRequest(endpoint + scopeId, accessToken)
                    .PUT(HttpRequest.BodyPublishers.noBody())
                    .build();

            var response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            assertResponse(response);
        }
    }

    private void createGroups(String accessToken) throws IOException, InterruptedException {
        createGroup(accessToken, "test-admins");
        createGroup(accessToken, "test-users");
    }

    private void createGroup(String accessToken, String groupName) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/groups";
        postJson(endpoint, accessToken, Map.of("name", groupName));
    }

    private void assignUsersToGroups(String accessToken) throws IOException, InterruptedException {
        var aliceId = getUserId(accessToken, "alice@example.org");
        var bobId = getUserId(accessToken, "bob@example.org");
        var adminGroupId = getGroupId(accessToken, "test-admins");
        var userGroupId = getGroupId(accessToken, "test-users");

        assignUserToGroup(accessToken, aliceId, adminGroupId);
        assignUserToGroup(accessToken, bobId, userGroupId);
    }

    private String getUserId(String accessToken, String username) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/users?username=" + username;
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var users = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        if (users.isEmpty()) {
            throw new RuntimeException("User not found: " + username);
        }
        return (String) users.get(0).get("id");
    }

    private String getGroupId(String accessToken, String groupName) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/groups";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var groups = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        for (var group : groups) {
            if (group.get("name").equals(groupName)) {
                return (String) group.get("id");
            }
        }
        throw new RuntimeException("Group not found: " + groupName);
    }

    private void assignUserToGroup(String accessToken, String userId, String groupId)
            throws IOException, InterruptedException {

        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/users/" + userId + "/groups/" + groupId;
        var request = buildRequest(endpoint, accessToken)
                .PUT(HttpRequest.BodyPublishers.noBody())
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        assertResponse(response);
    }

    private String getAdminAccessToken() throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/realms/master/protocol/openid-connect/token";
        var request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "grant_type=password&client_id=admin-cli&username=" + KEYCLOAK_ADMIN_USER +
                                "&password=" + KEYCLOAK_ADMIN_PASSWORD))
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        var token = objectMapper.readValue(response.body(), Map.class);
        return (String) token.get("access_token");
    }

    private void createRealm(String accessToken) throws IOException, InterruptedException {
        if (realmExists(accessToken, realmName)) {
            return;
        }

        var realmEndpoint = getAuthServerUrl() + "/admin/realms";
        postJson(realmEndpoint, accessToken, Map.of("realm", realmName, "enabled", true));
    }

    private boolean realmExists(String accessToken, String realmName) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var realms = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        return realms.stream().anyMatch(realm -> realm.get("realm").equals(realmName));
    }

    private void createClient(String accessToken) throws IOException, InterruptedException {
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalArgumentException("redirectUris are required");
        }

        if (clientExists(accessToken, clientId)) {
            return;
        }

        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/clients";
        postJson(endpoint, accessToken, Map.of(
                "clientId", clientId,
                "secret", clientSecret,
                "directAccessGrantsEnabled", true,
                "publicClient", false,
                "redirectUris", redirectUris,
                "serviceAccountsEnabled", true,
                "fullScopeAllowed", true));
    }

    private boolean clientExists(String accessToken, String clientId) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/clients";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var clients = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        return clients.stream().anyMatch(client -> client.get("clientId").equals(clientId));
    }

    private String getClientId(String accessToken) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/clients";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var clients = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        for (var client : clients) {
            if (client.get("clientId").equals(this.clientId)) {
                return (String) client.get("id");
            }
        }
        throw new RuntimeException("Client not found");
    }

    private String getClientScopeId(String accessToken, String scopeName) throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/client-scopes";
        var request = buildRequest(endpoint, accessToken)
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var scopes = objectMapper.readValue(response.body(), LIST_OF_JSON_OBJECTS);

        for (var scope : scopes) {
            if (scope.get("name").equals(scopeName)) {
                return (String) scope.get("id");
            }
        }

        throw new RuntimeException("Scope not found: " + scopeName);
    }

    private void createTestUsers(String accessToken) throws IOException, InterruptedException {
        createUser(accessToken, "alice@example.org", "password", "Alice", "Anderson");
        createUser(accessToken, "bob@example.org", "password", "Bob", "Brown");
    }

    private void createUser(String accessToken, String username, String password, String firstName, String lastName)
            throws IOException, InterruptedException {
        var endpoint = getAuthServerUrl() + "/admin/realms/" + realmName + "/users";
        postJson(endpoint, accessToken, Map.of(
                "username", username,
                "enabled", true,
                "email", username,
                "firstName", firstName,
                "lastName", lastName,
                "credentials", List.of(
                        Map.of(
                                "type", "password",
                                "value", password,
                                "temporary", false))));
    }

    private void postJson(String endpoint, String accessToken, Object body) throws IOException, InterruptedException {
        var json = objectMapper.writeValueAsString(body);

        var request = buildRequest(endpoint, accessToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertResponse(response);
    }

    private void putJson(String endpoint, String accessToken, Object body) throws IOException, InterruptedException {
        var json = objectMapper.writeValueAsString(body);

        var request = buildRequest(endpoint, accessToken)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(json))
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertResponse(response);
    }

    private String getAuthServerUrl() {
        return String.format("http://%s:%d", getHost(), getMappedPort(KEYCLOAK_PORT));
    }

    private static HttpRequest.Builder buildRequest(String endpoint, String accessToken) {
        return HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Authorization", "Bearer " + accessToken);
    }

    private static void assertResponse(HttpResponse<?> response) {
        if (response.statusCode() >= 300) {
            throw new RuntimeException("Keycloak API error: " + response.body());
        }
    }
}
