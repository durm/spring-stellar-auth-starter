package ru.bitsouth.libs.springstellarauthstarter.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import ru.bitsouth.libs.springstellarauthstarter.services.StellarIntegrationService;


@Controller
@RequestMapping
@Validated
@RequiredArgsConstructor
public class StellarTomlController {
    private final StellarIntegrationService service;

    @GetMapping("/.well-known/Stellar.toml")
    @ResponseBody
    public String toml() {
        return service.getToml();
    }
}
