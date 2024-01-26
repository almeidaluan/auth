package br.com.microservice.statelessauthapi.controller;

import br.com.microservice.statelessauthapi.core.model.DTO.AuthRequest;
import br.com.microservice.statelessauthapi.core.model.DTO.TokenDTO;
import br.com.microservice.statelessauthapi.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("login")
    private TokenDTO login(@RequestBody AuthRequest authRequest){
        return authService.login(authRequest);
    }


    @PostMapping("token/validate")
    private TokenDTO validateToken(@RequestHeader String accessToken){
        return authService.validateToken(accessToken);
    }
}
