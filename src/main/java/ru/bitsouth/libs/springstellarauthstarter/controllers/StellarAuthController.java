package ru.bitsouth.libs.springstellarauthstarter.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.ChallengeResponse;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.JwtTokenRequest;
import ru.bitsouth.libs.springstellarauthstarter.controllers.models.JwtTokenResponse;
import ru.bitsouth.libs.springstellarauthstarter.services.StellarIntegrationService;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@RestController
@RequestMapping
@Validated
@RequiredArgsConstructor
public class StellarAuthController {
    private final StellarIntegrationService service;

    @GetMapping("/auth")
    public @NotNull @Valid ChallengeResponse getChallenge(
            @RequestParam("account") @NotBlank String publicKey,
            @RequestParam(value = "home_domain", required = false) String home_domain
    ) {
        return ChallengeResponse.builder()
                .transaction(service.getChallenge(publicKey, home_domain))
                .build();
    }

    @PostMapping("/auth")
    public @NotNull @Valid JwtTokenResponse getJwtToken(
            @RequestBody @NotNull @Valid JwtTokenRequest jwtTokenRequest
    ) {
        return JwtTokenResponse.builder()
                .token(service.getJwtToken(jwtTokenRequest.getTransaction()))
                .build();
    }
}
