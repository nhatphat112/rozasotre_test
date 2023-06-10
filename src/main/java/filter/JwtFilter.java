package filter;


import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import utils.JwtHelper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private JwtHelper jwtHelper;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String headerToken = request.getHeader("Authorization");
        String token = "";
        if(headerToken.startsWith("Bearer ")){
            token = headerToken.substring(6);
        }
        try {
            Claims claims = jwtHelper.decodeToken(token);
            if(claims!=null){
                SecurityContext securityContext = SecurityContextHolder.getContext();
                securityContext.setAuthentication(new UsernamePasswordAuthenticationToken("","",new ArrayList<>()));
            }
        }catch (Exception e){
            System.out.println("Error at doFilterInternal");

        }
        filterChain.doFilter(request,response);
    }
}
