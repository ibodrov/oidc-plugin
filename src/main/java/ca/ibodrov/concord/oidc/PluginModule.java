package ca.ibodrov.concord.oidc;

import com.google.inject.Binder;
import com.google.inject.Module;
import com.walmartlabs.concord.server.boot.FilterChainConfigurator;
import com.walmartlabs.concord.server.boot.filters.AuthenticationHandler;
import org.apache.shiro.realm.Realm;

import javax.inject.Named;

import static com.google.inject.multibindings.Multibinder.newSetBinder;
import static com.walmartlabs.concord.server.Utils.bindJaxRsResource;

@Named
public class PluginModule implements Module {

    @Override
    public void configure(Binder binder) {
        newSetBinder(binder, FilterChainConfigurator.class).addBinding().to(OidcFilterChainConfigurator.class);
        newSetBinder(binder, AuthenticationHandler.class).addBinding().to(OidcAuthenticationHandler.class);
        newSetBinder(binder, Realm.class).addBinding().to(OidcRealm.class);
        bindJaxRsResource(binder, OidcResource.class);
    }
}
