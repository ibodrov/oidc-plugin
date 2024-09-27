package ca.ibodrov.concord.oidc;

import com.walmartlabs.concord.server.boot.filters.AuthenticationHandler;
import org.apache.shiro.authc.AuthenticationToken;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

import static ca.ibodrov.concord.oidc.Utils.encode;

public class OidcAuthenticationHandler implements AuthenticationHandler {

    static final String TOKEN_SESSION_KEY = "ca.ibodrov.concord.oidc/token";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    public AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        var req = (HttpServletRequest) request;

        var bearerToken = Optional.ofNullable(req.getHeader("Authorization"))
                .map(String::trim)
                .filter(h -> h.startsWith(BEARER_PREFIX))
                .map(h -> h.substring(BEARER_PREFIX.length()))
                .map(accessToken -> new OidcToken(Optional.empty(), accessToken));

        var sessionToken = Optional.ofNullable(req.getSession(false))
                .map(s -> (OidcToken) s.getAttribute(TOKEN_SESSION_KEY));

        return bearerToken.or(() -> sessionToken).orElse(null);
    }

    @Override
    public boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        var req = (HttpServletRequest) request;
        var resp = (HttpServletResponse) response;

        var from = req.getRequestURI();
        resp.sendRedirect("/api/ca.ibodrov.concord.oidc/authorize?from=" + encode(from));

        return true;
    }
}
