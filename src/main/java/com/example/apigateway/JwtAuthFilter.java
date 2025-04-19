package com.example.apigateway;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter {

    @Value("${jwt.secretKey}")
    private String key;

    private static final List<String> ALLOWED_PATH = List.of(
        "/member/create",
        "/member/doLogin",
        "/member/refresh-token",
        "/product/list"
    );// 상품 목록 조회는 로그인 한 회원이 아니더라도 가능

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String path = exchange.getRequest().getURI().getRawPath();

        System.out.println(path);

        if(ALLOWED_PATH.contains(path)){
            return chain.filter(exchange);
        }

        try {

            if(bearerToken == null){
                throw new IllegalArgumentException("token 관련 예외 발생");
            }

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(bearerToken)
                    .getBody();

            String userId = claims.getSubject();
            String role = claims.get("role", String.class);
        
            // 게이트웨이 서버에서 파싱된 JWT 정보를 다시 요청 객체 헤더에 삽입
            ServerWebExchange modifiedExchange = exchange
                    .mutate()
                    .request(
                            builder -> builder
                                    .header("X-User-Id", userId)
                                    .header("X-User-Role", "ROLE_" + role)
                    )
                    .build();

            return chain.filter(modifiedExchange);
            
        }catch (IllegalArgumentException | MalformedJwtException
                | ExpiredJwtException | SignatureException |
                UnsupportedJwtException e) {
            e.printStackTrace();
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

}
