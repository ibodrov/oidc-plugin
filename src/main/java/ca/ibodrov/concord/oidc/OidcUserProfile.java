package ca.ibodrov.concord.oidc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
public record OidcUserProfile(String email, String name, Set<String> groups) implements Serializable {
}
