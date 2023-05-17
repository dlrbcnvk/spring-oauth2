package springsecurity.oauth2.oauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Controller
@RequiredArgsConstructor
public class ClientHomeController {

    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/clientHome")
    public String clientHome() {
        return "clientHome";
    }

    @GetMapping("/client")
    public String client(HttpServletRequest request, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String clientRegistrationId = "keycloak";
        OAuth2AuthorizedClient authorizedClient1 = oAuth2AuthorizedClientRepository
                .loadAuthorizedClient(clientRegistrationId, authentication, request);

//        OAuth2AuthorizedClient authorizedClient2 = oAuth2AuthorizedClientService.loadAuthorizedClient(clientRegistrationId, authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient1.getAccessToken();
        ClientRegistration clientRegistration = authorizedClient1.getClientRegistration();

        // 사용자 정보 요청하기
        OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(clientRegistration, accessToken));
        OAuth2AuthenticationToken auth2AuthenticationToken = new OAuth2AuthenticationToken(
                oAuth2User,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")),
                clientRegistration.getRegistrationId());

        // 여기에 인증객체가 들어있는지를 가지고 인증이 되었는지를 판단함
        SecurityContextHolder.getContext().setAuthentication(auth2AuthenticationToken);

        model.addAttribute("accessToken", accessToken.getTokenValue());
        model.addAttribute("refreshToken", authorizedClient1.getRefreshToken().getTokenValue());
        model.addAttribute("principalName", oAuth2User.getName());
        model.addAttribute("clientName", authorizedClient1.getClientRegistration().getClientName());

        return "client";
    }
}
