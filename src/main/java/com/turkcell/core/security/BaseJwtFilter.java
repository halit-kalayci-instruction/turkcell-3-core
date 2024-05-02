package com.turkcell.core.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


import java.io.IOException;
import java.util.List;

@Component
public class BaseJwtFilter extends OncePerRequestFilter
{
  private final BaseJwtService jwtService;

  public BaseJwtFilter(BaseJwtService jwtService) {
    this.jwtService = jwtService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException
  {
    String jwtHeader = request.getHeader("Authorization");

    if(jwtHeader != null && jwtHeader.startsWith("Bearer "))
    {
      String jwt = jwtHeader.substring(7);

      if(jwtService.validateToken(jwt))
      {
        // Security paketini giriş yapılmış olarak güncellemek.
        String username = jwtService.extractUsername(jwt);

        List<String> roles = jwtService.extractRoles(jwt);

        List<SimpleGrantedAuthority> authorities = roles
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
        token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(token);
      }
    }


    filterChain.doFilter(request, response);
  }
}

