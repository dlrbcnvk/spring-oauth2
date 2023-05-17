package springsecurity.oauth2.oauth2client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


@Slf4j
public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    // 웹요청이 이 uri하고 매칭이 되면 이 필터를 동작하겠다
    public static final String DEFAULT_FILTER_PROCESSES_URI = "/oauth2Login/**";

    private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    private OAuth2AuthorizationSuccessHandler successHandler;

    private Duration clockSkew = Duration.ofSeconds(3600);
    private Clock clock = Clock.systemUTC();

    public CustomOAuth2AuthenticationFilter(DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
                                            OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        super(DEFAULT_FILTER_PROCESSES_URI);
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;

        this.successHandler = (authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository
                    .saveAuthorizedClient(authorizedClient, principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            log.info("authorizedClient={}", authorizedClient);
            log.info("principal={}", principal);
            log.info("attributes={}", attributes);
        };
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // AnonymousAuthenticationFilter보다 앞에 있어서 인증객체가 null일 수 있음

        if (authentication == null) {
            // 익명사용자 인증객체 만들기
            authentication =
                    new AnonymousAuthenticationToken("anonymous", "anonymousUser",
                            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        }

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

            // 인증객체가 바뀌었기 때문에 handler를 다시 만들어줘야 함
            this.successHandler.onAuthorizationSuccess(authorizedClient, oAuth2AuthenticationToken,
                    createAttributes(request, response));

            return oAuth2AuthenticationToken;
        }
        return null;
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    private static Map<String, Object> createAttributes(HttpServletRequest servletRequest,
                                                        HttpServletResponse servletResponse) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), servletRequest);
        attributes.put(HttpServletResponse.class.getName(), servletResponse);
        return attributes;
    }
}
