package ru.bitsouth.libs.springstellarauthstarter.controllers.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.lang.Nullable;

import javax.validation.constraints.NotBlank;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChallengeResponse {
    @NotBlank
    String transaction;
    @Nullable
    String networkPassphrase;
}
