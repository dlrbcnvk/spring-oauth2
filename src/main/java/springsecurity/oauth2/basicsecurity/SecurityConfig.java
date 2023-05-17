package springsecurity.oauth2.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@EnableWebSecurity
public class SecurityConfig {
//    @Bean
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
        http.formLogin();
        http.httpBasic();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

//        http.exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint() {
//            @Override
//            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                System.out.println("custom entryPoint");
//            }
//        });

//        http.apply(new CustomSecurityConfigurer().setFlag(true));
        return http.build();
    }

//    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
        http.httpBasic();
//        http.apply(new CustomSecurityConfigurer().setFlag(true));

        return http.build();
    }

}
