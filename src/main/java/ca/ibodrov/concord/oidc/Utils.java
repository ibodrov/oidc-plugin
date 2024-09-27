package ca.ibodrov.concord.oidc;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

final class Utils {

    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Utils() {
    }
}
