package springsecurity.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

//@RestController
@RequiredArgsConstructor
@Slf4j
public class IndexController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {

//        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
//        String clientId = clientRegistration.getClientId();
//        log.info("clientId={}", clientId);
//        String redirectUri = clientRegistration.getRedirectUri();
//        log.info("redirectUri={}", redirectUri);
        return "index";
    }

    @GetMapping("/user")
    public OAuth2User user(@RequestParam String accessToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);
        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, oAuth2AccessToken);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);
        return oAuth2User;
    }

    @GetMapping("/oidc")
    public OAuth2User oidc(@RequestParam String accessToken, @RequestParam String idToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
        idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
        idTokenClaims.put("preferred_username", "user");

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims);

        OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(oidcUserRequest);
        return oidcUser;
    }

    @GetMapping("/usermvc")
    public OAuth2User user(Authentication authentication) {
        OAuth2AuthenticationToken authentication1 = (OAuth2AuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken authentication2 = (OAuth2AuthenticationToken) authentication;
        boolean isSame = authentication1.equals(authentication2);
        OAuth2User oAuth2User = (OAuth2User) authentication2.getPrincipal();
        return oAuth2User;
    }

    @GetMapping("/oauth2User")
    public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("oAuth2User={}", oAuth2User);
        return oAuth2User;
    }

    @GetMapping("/oidcUser")
    public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        log.info("oidcUser={}", oidcUser);
        return oidcUser;
    }

}
