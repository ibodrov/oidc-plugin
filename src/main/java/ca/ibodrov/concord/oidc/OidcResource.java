package ca.ibodrov.concord.oidc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.walmartlabs.concord.server.oidc.PluginConfiguration;
import com.walmartlabs.concord.server.sdk.rest.Resource;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;

import static ca.ibodrov.concord.oidc.Utils.encode;
import static java.util.Objects.requireNonNull;

@Path("/api/ca.ibodrov.concord.oidc")
public class OidcResource implements Resource {

    private static final String FROM_SESSION_KEY = "ca.ibodrov.concord.oidc/from";

    private final URI authorizationUri;
    private final URI redirectUri;
    private final URI tokenUri;
    private final URI logOutUri;
    private final URI afterLoginUri;
    private final URI onErrorUri;
    private final String clientId;
    private final String clientSecret;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Inject
    public OidcResource(PluginConfiguration cfg) throws URISyntaxException {
        requireNonNull(cfg);

        this.authorizationUri = buildAuthorizationUri(cfg);
        this.redirectUri = URI.create(cfg.redirectUri());
        this.tokenUri = URI.create(cfg.tokenUri());
        this.logOutUri = URI.create(cfg.logOutUri());
        this.afterLoginUri = URI.create(cfg.afterLoginUri());
        this.onErrorUri = URI.create(cfg.onErrorUri());
        this.clientId = cfg.clientId();
        this.clientSecret = cfg.clientSecret();
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    @GET
    @Path("/authorize")
    public Response authorize(@QueryParam("from") String from,
                              @Context HttpServletRequest request) {
        if (from != null && !from.isBlank()) {
            var session = request.getSession(true);
            session.setAttribute(FROM_SESSION_KEY, from);
        }
        return Response.seeOther(authorizationUri).build();
    }

    private Response redirectToErrorPage(String error) {
        return Response.seeOther(onErrorUri.resolve("?error=" + encode(error))).build();
    }

    @GET
    @Path("/callback")
    public Response callback(@QueryParam("code") String code,
                             @QueryParam("state") String state,
                             @QueryParam("error") String error,
                             @Context HttpServletRequest request) {

        // TODO handle "state"

        if (error != null) {
            return redirectToErrorPage(error);
        }

        if (code == null) {
            return redirectToErrorPage("missing_code");
        }

        TokenResponse resp;
        try {
            resp = getAccessToken(code);
        } catch (IOException | InterruptedException e) {
            return redirectToErrorPage("access_token_fetch_error");
        }

        var token = new OidcToken(Optional.of(resp.idToken()), resp.accessToken());

        var session = request.getSession(true);
        session.setAttribute(OidcAuthenticationHandler.TOKEN_SESSION_KEY, token);

        var from = Optional.ofNullable((String) session.getAttribute(FROM_SESSION_KEY))
                .map(URI::create)
                .orElse(null);
        var target = from != null ? from : afterLoginUri;

        return Response.seeOther(target).build();
    }

    @GET
    @Path("/logout")
    public Response logout(@Context HttpServletRequest req, @Context UriInfo uriInfo) {
        var session = req.getSession(false);
        if (session != null) {
            var token = (OidcToken) session.getAttribute(OidcAuthenticationHandler.TOKEN_SESSION_KEY);
            session.invalidate();

            if (token != null) {
                try {
                    var uri = buildLogoutUri(token.id(), uriInfo);
                    return Response.seeOther(uri).build();
                } catch (URISyntaxException e) {
                    throw new WebApplicationException("Invalid logout URI %s: %s".formatted(logOutUri, e.getMessage()),
                            Status.INTERNAL_SERVER_ERROR);
                }
            }
        }

        return Response.seeOther(authorizationUri).build();
    }

    private TokenResponse getAccessToken(String code) throws IOException, InterruptedException {
        var formData = String.join("&", List.of(
                "grant_type=authorization_code",
                "code=" + encode(code),
                "redirect_uri=" + redirectUri.toASCIIString(),
                "client_id=" + encode(clientId),
                "client_secret=" + encode(clientSecret)));

        var req = HttpRequest.newBuilder()
                .uri(tokenUri)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .POST(BodyPublishers.ofString(formData))
                .build();

        var resp = httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
        if (resp.statusCode() != 200) {
            throw new IOException("Token error (%s): %s".formatted(resp.statusCode(), resp.body()));
        }

        var body = objectMapper.readValue(resp.body(), TokenResponse.class);
        if (body.idToken() == null) {
            throw new IOException("Missing ID token in the response: %s".formatted(body));
        }
        if (body.accessToken() == null) {
            throw new IOException("Missing access token in the response: %s".formatted(body));
        }

        return body;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(@JsonProperty("id_token") String idToken,
            @JsonProperty("access_token") String accessToken) {
    }

    private URI buildLogoutUri(Optional<String> idToken, UriInfo uriInfo) throws URISyntaxException {
        var postLogoutRedirectUri = uriInfo.getBaseUriBuilder().path("/api/ca.ibodrov.concord.oidc/authorize").build();

        var params = "post_logout_redirect_uri=" + postLogoutRedirectUri;
        if (idToken.isPresent()) {
            params += "&id_token_hint=" + idToken.get();
        }
        return new URI(logOutUri.getScheme(), logOutUri.getAuthority(), logOutUri.getPath(), params, null);
    }

    private static URI buildAuthorizationUri(PluginConfiguration cfg) throws URISyntaxException {
        var uri = URI.create(cfg.authorizationUri());

        var params = String.join("&", List.of(
                "client_id=" + cfg.clientId(),
                "response_type=code",
                "scope=openid profile email groups",
                "redirect_uri=" + cfg.redirectUri()));

        if (uri.getQuery() != null) {
            params = uri.getQuery() + "&" + params;
        }

        return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), params, null);
    }
}
