package ca.ibodrov.concord.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Map;

import static ca.ibodrov.concord.oidc.Utils.encode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class IntegrationTests {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static TestingServers servers;

    @BeforeAll
    public static void setUp() throws Exception {
        servers = new TestingServers();
        servers.start(findAvailablePort(9001, 59001), Map.of());
    }

    @AfterAll
    public static void tearDown() throws Exception {
        servers.close();
    }

    @Test
    public void passwordCredentialsFlowMustBeSupported() throws Exception {
        var aliceToken = getAccessToken("alice@example.org", "password");
        var bobToken = getAccessToken("bob@example.org", "password");

        assertEquals("alice@example.org", whoami(aliceToken));
        assertEquals("bob@example.org", whoami(bobToken));
        assertThrows(Exception.class, () -> whoami("invalid-token"));
    }

    private static int findAvailablePort(int minPort, int maxPort) {
        for (int port = minPort; port <= maxPort; port++) {
            try (var socket = new ServerSocket(port)) {
                return socket.getLocalPort();
            } catch (IOException e) {
            }
        }
        throw new RuntimeException("No available port found in range " + minPort + " - " + maxPort);
    }

    private String getAccessToken(String username, String password) throws Exception {
        var clientId = servers.getKeycloakContainer().getClientId();
        var clientSecret = servers.getKeycloakContainer().getClientSecret();
        var tokenEndpoint = servers.getKeycloakContainer().getTokenUrl();

        var client = HttpClient.newHttpClient();

        var formData = String.format("grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
                encode(clientId),
                encode(clientSecret),
                encode(username),
                encode(password));

        var request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formData))
                .build();

        var response = client.send(request, BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }

        var json = objectMapper.readTree(response.body());
        if (!json.isObject()) {
            throw new IllegalStateException("Unexpected response: " + json);
        }

        var data = (ObjectNode) json;
        if (data.has("error")) {
            throw new IllegalStateException("Error response: " + data);
        }

        var accessToken = data.get("access_token").asText();
        if (accessToken == null) {
            throw new IllegalStateException("No access token in the response: " + data);
        }

        return accessToken;
    }

    private String whoami(String token) throws Exception {
        var client = HttpClient.newHttpClient();
        var request = HttpRequest.newBuilder()
                .uri(URI.create(
                        "http://localhost:%s/api/service/console/whoami".formatted(servers.getServer().getApiPort())))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();

        var response = client.send(request, BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }

        var json = objectMapper.readTree(response.body());
        if (!json.isObject()) {
            throw new IllegalStateException("Unexpected response: " + json);
        }

        var data = (ObjectNode) json;
        var username = data.get("username").asText();
        if (username == null) {
            throw new IllegalStateException("No username in the response: " + data);
        }

        return username;
    }
}
