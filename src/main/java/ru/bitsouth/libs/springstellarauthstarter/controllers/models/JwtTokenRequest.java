package ru.bitsouth.libs.springstellarauthstarter.controllers.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtTokenRequest {
    @NotBlank
    String transaction;
}
