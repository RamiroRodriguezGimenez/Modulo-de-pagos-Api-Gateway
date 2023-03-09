package com.paymentmodul.apigateway.security;

import io.netty.resolver.DefaultAddressResolverGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.AuthorizeExchangeDsl;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.netty.http.client.HttpClient;

@EnableWebFluxSecurity
public class SpringSecurityConfig {
    @Bean
    public HttpClient httpClient() {
        return HttpClient.create().resolver(DefaultAddressResolverGroup.INSTANCE);
    }
    @Autowired
    private JwtAuthenticationFilter authenticationFilter;
    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http){
        return http.authorizeExchange()
                .pathMatchers("/service-oauth/oauth/**").permitAll()
                .pathMatchers(HttpMethod.POST,"/client-service/api/client/register").permitAll()
                .pathMatchers(HttpMethod.GET, "/client-service/**","/account-service/**","/payment-service/**").hasAnyRole("ADMIN","USER")
                .pathMatchers(HttpMethod.POST, "/client-service/**","/account-service/**","/payment-service/**").hasAnyRole("ADMIN","USER")
                .pathMatchers(HttpMethod.PUT, "/client-service/**","/account-service/**","/payment-service/**").hasAnyRole("ADMIN","USER")
                .anyExchange().authenticated()
                .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable()
                .build();
    }
}
