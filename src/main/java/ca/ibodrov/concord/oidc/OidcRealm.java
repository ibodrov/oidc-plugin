package ca.ibodrov.concord.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.walmartlabs.concord.server.oidc.PluginConfiguration;
import com.walmartlabs.concord.server.sdk.ConcordApplicationException;
import com.walmartlabs.concord.server.security.SecurityUtils;
import com.walmartlabs.concord.server.security.UserPrincipal;
import com.walmartlabs.concord.server.user.UserManager;
import com.walmartlabs.concord.server.user.UserType;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import javax.inject.Inject;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class OidcRealm extends AuthorizingRealm {

    private static final String REALM_NAME = "ca.ibodrov.concord.oidc";

    private final UserManager userManager;
    private final URI userInfoUri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Inject
    public OidcRealm(PluginConfiguration cfg, UserManager userManager) {
        requireNonNull(cfg);

        this.userManager = requireNonNull(userManager);
        this.userInfoUri = URI.create(cfg.userInfoUri());
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof OidcToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        var principal = principals.oneByType(UserPrincipal.class);
        if (!REALM_NAME.equals(principal.getRealm())) {
            return null;
        }

        // TODO role mapping

        return SecurityUtils.toAuthorizationInfo(principals, List.of());
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
            throws AuthenticationException {

        var token = (OidcToken) authenticationToken;

        OidcUserProfile profile;
        try {
            profile = fetchUserProfile(token.accessToken());
        } catch (IOException | InterruptedException e) {
            throw new AuthenticationException("Error while fetching user profile", e);
        }

        var username = profile.email().toLowerCase();
        var userEntry = userManager.getOrCreate(username, null, UserType.LOCAL)
                .orElseThrow(() -> new ConcordApplicationException("User not found: " + profile.email()));

        userManager.update(userEntry.getId(), profile.name(), profile.email(), null, false, null);

        // TODO team mapping

        var principal = new UserPrincipal(REALM_NAME, userEntry);
        return new SimpleAccount(Arrays.asList(principal, token, profile), token, getName());
    }

    private OidcUserProfile fetchUserProfile(String accessToken) throws IOException, InterruptedException {
        var req = HttpRequest.newBuilder()
                .uri(userInfoUri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .GET()
                .build();

        var resp = httpClient.send(req, BodyHandlers.ofInputStream());
        if (resp.statusCode() != 200) {
            throw new IOException("Profile fetch error (%s): %s".formatted(resp.statusCode(), resp.body()));
        }

        return objectMapper.readValue(resp.body(), OidcUserProfile.class);
    }
}
