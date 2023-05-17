package springsecurity.oauth2.oauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Objects;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/home")
    public String home(Model model, OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient("keycloak", authentication.getName());
        model.addAttribute("OAuth2AuthenticationToken", authentication);
        model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("refreshToken", Objects.requireNonNull(authorizedClient.getRefreshToken()).getTokenValue());



        return "home";
    }
}
