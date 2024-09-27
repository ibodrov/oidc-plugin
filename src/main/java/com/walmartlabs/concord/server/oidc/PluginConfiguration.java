/** TODO move to another package once there is support for that */
package com.walmartlabs.concord.server.oidc;

import com.walmartlabs.ollie.config.Config;

import javax.inject.Inject;

import static java.util.Objects.requireNonNull;

/**
 * @param authorizationUri OIDC provider's authorization endpoint
 * @param tokenUri         OIDC provider's token endpoint
 * @param userInfoUri      OIDC provider's user info endpoint
 * @param logOutUri        OIDC provider's logout endpoint
 * @param redirectUri      Callback URL
 * @param afterLoginUri    Redirect URL after successful login
 * @param onErrorUri       Redirect URL after an error (must handle an "error"
 *                         query parameter)
 * @param clientId         OIDC client ID
 * @param clientSecret     OIDC client secret
 */
public record PluginConfiguration(String authorizationUri,
        String tokenUri,
        String userInfoUri,
        String logOutUri,
        String redirectUri,
        String afterLoginUri,
        String onErrorUri,
        String clientId,
        String clientSecret) {

    @Inject
    public PluginConfiguration(
                               @Config("oidc.authorizationUri") String authorizationUri,
                               @Config("oidc.tokenUri") String tokenUri,
                               @Config("oidc.userInfoUri") String userInfoUri,
                               @Config("oidc.logOutUri") String logOutUri,
                               @Config("oidc.redirectUri") String redirectUri,
                               @Config("oidc.afterLoginUri") String afterLoginUri,
                               @Config("oidc.onErrorUri") String onErrorUri,
                               @Config("oidc.clientId") String clientId,
                               @Config("oidc.secret") String clientSecret) {

        this.authorizationUri = requireNonNull(authorizationUri);
        this.tokenUri = requireNonNull(tokenUri);
        this.userInfoUri = requireNonNull(userInfoUri);
        this.logOutUri = requireNonNull(logOutUri);
        this.redirectUri = requireNonNull(redirectUri);
        this.afterLoginUri = requireNonNull(afterLoginUri);
        this.onErrorUri = requireNonNull(onErrorUri);
        this.clientId = requireNonNull(clientId);
        this.clientSecret = requireNonNull(clientSecret);
    }
}
