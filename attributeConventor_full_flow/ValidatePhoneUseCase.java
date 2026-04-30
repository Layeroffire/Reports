package com.nexus.usecase;

import com.nexus.domain.user.User;
import com.nexus.infrastructure.controller.dto.auth.ValidatePhoneResponse;
import com.nexus.usecase.inport.ValidatePhoneInPort;
import com.nexus.usecase.outport.UserPersistenceOutPort;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class ValidatePhoneUseCase implements ValidatePhoneInPort {

  private final UserPersistenceOutPort userPersistenceOutPort;

  @Override
  public ValidatePhoneResponse invoke(String phoneNumber) {
    log.info("Validating phone number: {}", phoneNumber);

    Optional<User> user = userPersistenceOutPort.findByPhone(phoneNumber);

    if (user.isPresent()) {
      log.info("User found with phone number: {}, userId: {}", phoneNumber, user.get().getId());
      return ValidatePhoneResponse.builder().userId(user.get().getId()).exists(true).build();
    }

    log.info("User not found with phone number: {}", phoneNumber);
    return ValidatePhoneResponse.builder().exists(false).build();
  }
}
