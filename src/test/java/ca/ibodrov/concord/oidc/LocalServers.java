package ca.ibodrov.concord.oidc;

import java.util.Map;

public class LocalServers {

    private static final String TEST_ADMIN_TOKEN = "t3st";
    private static final int API_PORT = 8001;

    public static void main(String[] args) throws Exception {
        try (var server = new TestingServers()) {
            server.start(API_PORT, createConfig());

            var db = server.getDbContainer();
            System.out.printf("""
                    ==============================================================

                      UI (hosted): http://localhost:8001
                      OIDC authorization: http://localhost:8001/api/ca.ibodrov.concord.oidc/authorize
                      DB:
                        JDBC URL: %s
                        username: %s
                        password: %s
                      API:
                        admin key: %s

                    ==============================================================
                    %n""", db.getJdbcUrl(), db.getUsername(), db.getPassword(), TEST_ADMIN_TOKEN);

            Thread.currentThread().join();
        }
    }

    private static Map<String, String> createConfig() {
        return Map.of("db.changeLogParameters.defaultAdminToken", TEST_ADMIN_TOKEN);
    }
}
