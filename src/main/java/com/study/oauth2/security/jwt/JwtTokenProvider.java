package com.study.oauth2.security.jwt;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

	private final Key key;
	
	public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
		key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
	}
	
	public String generateOAuth2RegisterToken(Authentication authentication) {
		
		Date tokenExpiresDate = new Date(new Date().getTime() + (1000 * 60 * 10));
		
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		String email = oAuth2User.getAttributes();
		
		String registerToken = Jwts.builder()
								.setSubject("OAuth2Register")
								.claim("email", email)
								.compact();
		
		return registerToken;
	}
}
