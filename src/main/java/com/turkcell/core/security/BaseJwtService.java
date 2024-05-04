package com.turkcell.core.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class BaseJwtService
{
  private long EXPIRATION = 600000;
  private String SECRET_KEY = "r9qSZrihqYt79JPbHpAaD//OX8RICTOIRGPzESiHbiGT1Ppc4G1uMTbLu5Lw7/o6GSbtpEPZmzMELKH1G1qirjerCbpASu3DZYN1AsGgMZ9JEhSwzwYzfp0h8Ooqu2R1r/s2qiN+PxInHX1uee8yQcwBEIkaU9U3EUMvSYsdY+CBSWsIJeywC9p9hWJn1cBcFBBHjDQ0zJrEK6bwDfRI9DGatN+thR8OmEzER/RKyYv8AFQxeYsw3ZZC+nry2kgm5T48NlEyqhif0logyzAYvRAIpjhV+n/yXJe0D6CJOyMiPaYT217JHdStcD3THjVtGgIoF0mSWkOMFvLGdTLb4WYcx3jORFC+MshYzhDGFkY=";

  public String generateToken(String username, Map<String, Object> extraClaims)
  {
    String token = Jwts
            .builder()
            .subject(username)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
            .claims(extraClaims)
            .signWith(getSigningKey())
            .compact();
    return token;
  }
  public Boolean validateToken(String token)
  {
    return getTokenClaims(token).getExpiration().after(new Date()); // Kendi ürettiğim token mı?
  }
  public String extractUsername(String token)
  {
    return getTokenClaims(token).getSubject();
  }

  public List<String> extractRoles(String token)
  {
    return getTokenClaims(token).get("roles", List.class);
  }

  private Claims getTokenClaims(String token)
  {
    return Jwts
            .parser()
            .verifyWith((SecretKey) getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  private Key getSigningKey()
  {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}