package springsecurity.oauth2.oauth2login;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import springsecurity.oauth2.oauth2client.CustomOAuth2AuthenticationFilter;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class CustomOAuth2ClientConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    @Bean
    public SecurityFilterChain oauth2SecurityConfigChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(requests -> requests
                .antMatchers("/oauth2Login","/clientHome", "/client", "/").permitAll()
                .anyRequest().authenticated());

//        http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));

//        http.oauth2Login(oauth2 -> oauth2
////                .loginPage("/login")
//                .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig
//                        .baseUri("/oauth2/authorization")
//                        .authorizationRequestResolver(customOAuth2AuthorizationRequestResolver()))
//                .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig
//                        .baseUri("/login/oauth2/code/*")));

        http.oauth2Client(Customizer.withDefaults());

//        http.logout()
//                .logoutSuccessUrl("/clientHome")
//                .logoutSuccessHandler(oidcLogoutSuccessHandler())
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .deleteCookies("JSESSIONID");

        // oauth2Client 강의 후반부 custom filter 추가하기
        http.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter auth2AuthenticationFilter =
                new CustomOAuth2AuthenticationFilter(oAuth2AuthorizedClientManager, oAuth2AuthorizedClientRepository);

        auth2AuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });

        return auth2AuthenticationFilter;
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }

    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
        return successHandler;
    }
}
