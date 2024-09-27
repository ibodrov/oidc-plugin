package ca.ibodrov.concord.oidc;

import com.walmartlabs.concord.server.boot.FilterChainConfigurator;
import org.apache.shiro.web.filter.mgt.FilterChainManager;

public class OidcFilterChainConfigurator implements FilterChainConfigurator {

    @Override
    public void configure(FilterChainManager manager) {
        manager.createChain("/api/ca.ibodrov.concord.oidc/*", "anon");
    }
}
