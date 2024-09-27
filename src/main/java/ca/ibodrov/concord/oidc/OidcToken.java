package ca.ibodrov.concord.oidc;

import org.apache.shiro.authc.AuthenticationToken;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;

public record OidcToken(Optional<String> id, String accessToken)
        implements AuthenticationToken, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public Object getPrincipal() {
        return this;
    }

    @Override
    public Object getCredentials() {
        return this;
    }
}
