package ca.ibodrov.concord.oidc;

import com.google.inject.Module;
import com.typesafe.config.Config;
import com.walmartlabs.concord.it.testingserver.TestingConcordServer;
import com.walmartlabs.concord.server.console.ConsoleModule;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

public class TestingServers implements AutoCloseable {

    private static final String OIDC_AUTHORIZATION_URI = "http://localhost:%s/api/ca.ibodrov.concord.oidc/authorize";
    private static final String OIDC_REDIRECT_URI = "http://localhost:%s/api/ca.ibodrov.concord.oidc/callback";

    private final ExecutorService executor = Executors.newCachedThreadPool();

    private KeycloakContainer keycloakContainer;
    private PostgreSQLContainer<?> dbContainer;
    private TestingConcordServer server;

    public KeycloakContainer getKeycloakContainer() {
        return keycloakContainer;
    }

    public PostgreSQLContainer<?> getDbContainer() {
        return dbContainer;
    }

    public TestingConcordServer getServer() {
        return server;
    }

    public void start(int apiPort, Map<String, String> extraConfig) throws Exception {
        var authorizationUri = OIDC_AUTHORIZATION_URI.formatted(apiPort);
        var redirectUri = OIDC_REDIRECT_URI.formatted(apiPort);

        keycloakContainer = new KeycloakContainer().withRedirectUris(authorizationUri, redirectUri);
        dbContainer = new PostgreSQLContainer<>("postgres:15-alpine");

        var keycloakFuture = executor.submit(() -> keycloakContainer.start());
        var dbFuture = executor.submit(() -> dbContainer.start());

        keycloakFuture.get();
        dbFuture.get();

        var config = createConfig(keycloakContainer, apiPort, redirectUri);
        config = new HashMap<>(config);
        config.putAll(extraConfig);

        server = new TestingConcordServer(dbContainer, apiPort, config, modules());
        server.start();
    }

    public void stop() throws Exception {
        if (server != null) {
            server.stop();
        }

        if (dbContainer != null) {
            dbContainer.stop();
        }

        if (keycloakContainer != null) {
            keycloakContainer.stop();
        }
    }

    @Override
    public void close() throws Exception {
        stop();
    }

    private static Map<String, String> createConfig(KeycloakContainer keycloak, int apiPort, String redirectUri) {
        return Map.of(
                "oidc.enabled", "true", // TODO handle in the code
                "oidc.clientId", keycloak.getClientId(),
                "oidc.secret", keycloak.getClientSecret(),
                "oidc.authorizationUri", keycloak.getAuthorizationUrl(),
                "oidc.tokenUri", keycloak.getTokenUrl(),
                "oidc.userInfoUri", keycloak.getUserInfoUrl(),
                "oidc.logOutUri", keycloak.getLogOutUrl(),
                "oidc.redirectUri", redirectUri,
                "oidc.afterLoginUri", "http://localhost:%s".formatted(apiPort),
                "oidc.onErrorUri", "http://localhost:%s/#/unauthorized".formatted(apiPort));
    }

    private static List<Function<Config, Module>> modules() {
        return List.of(
                _cfg -> new PluginModule(),
                _cfg -> new ConsoleModule());
    }
}
