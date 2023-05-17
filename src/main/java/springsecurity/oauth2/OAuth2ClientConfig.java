package springsecurity.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.List;

/**
 * application.yml 대신 자바 클래스로 하는 설정클래스
 */
//@Configuration
public class OAuth2ClientConfig {

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
//    }
//
//    private ClientRegistration keycloakClientRegistration() {
//        return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
//                .registrationId("keycloak")
//                .clientId("oauth2-client-app")
//                .clientName("oauth2-client-app")
//                .clientSecret("zfSbFGa7hNwJiugxDShgg2RooC28h5JR")
//                .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
//                .scope("profile")
//                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
//                .userNameAttributeName("preferred_username")
//                .clientAuthenticationMethod(new ClientAuthenticationMethod("client_secret_basic"))
//                .build();
//    }
}
