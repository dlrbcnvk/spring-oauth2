package springsecurity.oauth2.oauth2client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    private Duration clockSkew = Duration.ofSeconds(3600);
    private Clock clock = Clock.systemUTC();

    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 익명 사용자 인증객체 일 것임

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository
                    .saveAuthorizedClient(authorizedClient, principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            log.info("authorizedClient={}", authorizedClient);
            log.info("principal={}", principal);
            log.info("attributes={}", attributes);
        };

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        // authorization_code, implicit, password
//        if (authorizedClient != null) {
//            // 인증객체 안에 있는 accessToken을 가지고 인가서버와 통신한 다음에
//            // 사용자 정보를 가져와서 인증 처리를 할 수 있음
//            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
//            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
//            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
//            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);
//
//            // 인가서버로부터 가져온 scope 값을 권한으로 매핑
//            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
//            authorityMapper.setPrefix("SCOPE_");
//            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());
//
//            // 인증처리 후속작업
//            // 인증객체 만들고, 인증객체를 SecurityContext 안에 저장하기
//            OAuth2AuthenticationToken oAuth2AuthenticationToken =
//                    new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, clientRegistration.getRegistrationId());
//
//            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
//            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
//        }

        // client_credentials
//        model.addAttribute("authorizedClientAccessToken", authorizedClient.getAccessToken().getTokenValue());

//        // refresh_token, 권한부여타입을 변경하지 않고 실행
//        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
//            log.info("refresh_token={}", authorizedClient.getRefreshToken());
//            model.addAttribute("authorizedClientAccessToken", authorizedClient.getRefreshToken().getTokenValue());
//            OAuth2AuthorizedClient authorizedClientAfter = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
//            model.addAttribute("authorizedClientAccessTokenAfter", authorizedClientAfter.getRefreshToken().getTokenValue());
//        }


        // refresh_token, 권한부여타입을 변경하고 실행
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
            ClientRegistration clientRegistration = ClientRegistration
                    .withClientRegistration(authorizedClient.getClientRegistration())
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();
            OAuth2AuthorizedClient oAuth2AuthorizedClient =
                    new OAuth2AuthorizedClient(clientRegistration, authorizedClient.getPrincipalName(),
                            authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());
            OAuth2AuthorizeRequest authorizeRequest2 = OAuth2AuthorizeRequest
                    .withAuthorizedClient(oAuth2AuthorizedClient)
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();
            OAuth2AuthorizedClient authorizedClient2 = oAuth2AuthorizedClientManager.authorize(authorizeRequest2);

        }

        return "home";
    }

    @GetMapping("/oauth2Login/v2")
    public String oauth2LoginV2(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient,
                              Model model) {

        // authorization_code, implicit, password
        if (authorizedClient != null) {
            // 인증객체 안에 있는 accessToken을 가지고 인가서버와 통신한 다음에
            // 사용자 정보를 가져와서 인증 처리를 할 수 있음
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

            // 인가서버로부터 가져온 scope 값을 권한으로 매핑
            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SCOPE_");
            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            // 인증처리 후속작업
            // 인증객체 만들고, 인증객체를 SecurityContext 안에 저장하기
            OAuth2AuthenticationToken oAuth2AuthenticationToken =
                    new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, clientRegistration.getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
        }

        return "home";
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletResponse response, HttpServletRequest request) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }
}
