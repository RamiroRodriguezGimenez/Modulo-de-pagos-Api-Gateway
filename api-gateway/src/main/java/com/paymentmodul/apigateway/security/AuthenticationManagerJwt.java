package com.paymentmodul.apigateway.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


@Component
public class AuthenticationManagerJwt implements ReactiveAuthenticationManager {

    private String llaveJwt="algun_codigo_secreto_aeiou";
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication.getCredentials().toString())
                .map(token -> {
                    SecretKey llave= Keys.hmacShaKeyFor(Base64.getEncoder().encode(llaveJwt.getBytes()));
                    return Jwts.parserBuilder().setSigningKey(llave).build().parseClaimsJws(token).getBody();
                } )
                .map(claims -> {
                    String username = claims.get("user_name",String.class);
                    List<String> roles = claims.get("authorities", List.class);
                    Collection<GrantedAuthority> authorities= roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
                    return new UsernamePasswordAuthenticationToken(username, null, authorities);
                });
    }
}
