package br.com.microservice.statelessauthapi.service;

import br.com.microservice.statelessauthapi.core.model.DTO.AuthRequest;
import br.com.microservice.statelessauthapi.core.model.DTO.TokenDTO;
import br.com.microservice.statelessauthapi.infra.exception.ValidationException;
import br.com.microservice.statelessauthapi.infra.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    //Caso eu queira criar uma senha criptografada eu preciso criar 1 user e chamar o passwordEncoder.encode(minhasenha)
    public TokenDTO login(AuthRequest authRequest){
        var user = userRepository.findByUsername(authRequest.username())
                .orElseThrow(()->new ValidationException("User not found"));

        var accessToken = jwtService.CreateToken(user);
        validatePassword(authRequest.password(),user.getPassword());
        return new TokenDTO(accessToken);
    }

    private void validatePassword(String rawpassword, String encodedPassword){
        if(!passwordEncoder.matches(rawpassword,encodedPassword)){
            throw new ValidationException("This password is incorrect");
        }
    }

    public TokenDTO validateToken(String accessToken){
            validateExistingToken(accessToken);
            jwtService.ValidateAccessToken(accessToken);
            return new TokenDTO(accessToken);
    }

    private void validateExistingToken(String accessToken){
        if(isEmpty(accessToken)){
            throw new ValidationException("The access token must he informed");
        }
    }

}
