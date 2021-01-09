package org.sid.secservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import org.sid.secservice.sec.entities.AppRole;
import org.sid.secservice.sec.entities.AppUser;
import org.sid.secservice.sec.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController

public class AccountRestController {

    AccountService accountService;
    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){

        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){

        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){

        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){

        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
    @PostMapping("/refreshToken")
    public Map<String, String> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            try {
                String jwtRefreshToken = token.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                System.out.printf("   hhhhhhhhhhhhhh  "+jwtRefreshToken+"   ffffffff");
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                System.out.printf(username);
                String jwtAccessToken = JWT
                        .create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 30 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(e -> e.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> idToken = new HashMap<>();
                idToken.put("access_Token", jwtAccessToken);
                idToken.put("refresh_Token", jwtRefreshToken);
                System.out.printf(idToken.toString());
                return idToken;
            } catch (TokenExpiredException e) {
                response.setHeader("Error-Message", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        throw new RuntimeException("Bad Refresh Token");
    }
}



@Data
class RoleUserForm{
    private String username;
    private String roleName;
}