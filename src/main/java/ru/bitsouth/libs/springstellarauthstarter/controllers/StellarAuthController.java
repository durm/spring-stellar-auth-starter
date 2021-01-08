package ru.bitsouth.libs.springstellarauthstarter.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.ChallengeResponse;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.JwtTokenRequest;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.JwtTokenResponse;
import ru.bitsouth.libs.springstellarauthstarter.services.StellarAuthService;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@RestController
@RequestMapping("/auth")
@Validated
@RequiredArgsConstructor
public class StellarAuthController {
    private final StellarAuthService service;

    @GetMapping
    public @NotNull @Valid ChallengeResponse getChallenge(
            @RequestParam("account") @NotBlank String publicKey,
            @RequestParam(value = "home_domain", required = false, defaultValue = "Sample auth") String homeDomain
    ) {
        return ChallengeResponse.builder()
                .transaction(service.getChallenge(publicKey, homeDomain))
                .build();
    }

    @PostMapping
    public @NotNull @Valid JwtTokenResponse getJwtToken(
            @RequestBody @NotNull @Valid JwtTokenRequest jwtTokenRequest
    ) {
        return JwtTokenResponse.builder()
                .token(service.getJwtToken(jwtTokenRequest.getTransaction()))
                .build();
    }
}
