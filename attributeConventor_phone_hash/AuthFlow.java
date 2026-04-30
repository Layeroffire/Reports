package com.nexus.infrastructure.config.security;

import static com.nexus.domain.account.AccountErrorCode.ACCOUNT_NOT_FOUND;
import static com.nexus.domain.officer.OfficerProfileErrorCode.OFFICER_PROFILE_NOT_FOUND;
import static com.nexus.domain.person.PersonErrorCode.PERSON_NOT_FOUND;
import static com.nexus.domain.user.UserErrorCode.USER_NOT_FOUND;

import com.nexus.domain.exception.DomainException;
import com.nexus.domain.user.Role;
import com.nexus.domain.user.UserLoginResponse;
import com.nexus.infrastructure.persistence.account.AccountEntity;
import com.nexus.infrastructure.persistence.account.AccountJpaRepository;
import com.nexus.infrastructure.persistence.officer.OfficerProfileEntity;
import com.nexus.infrastructure.persistence.officer.OfficerProfileJpaRepository;
import com.nexus.infrastructure.persistence.person.PersonEntity;
import com.nexus.infrastructure.persistence.person.PersonJpaRepository;
import com.nexus.infrastructure.security.crypto.AttributeHashingService;
import com.nexus.infrastructure.persistence.user.UserEntity;
import com.nexus.infrastructure.persistence.user.UserJpaRepository;
import com.nexus.usecase.outport.UserAuthorizationOutPort;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService implements UserAuthorizationOutPort {

  private final AuthenticationManager authenticationManager;
  private final UserJpaRepository userJpaRepository;
  private final AccountJpaRepository accountJpaRepository;
  private final PersonJpaRepository personJpaRepository;
  private final OfficerProfileJpaRepository officerProfileJpaRepository;
  private final JwtConfig jwtConfig;

  @Override
  public UserLoginResponse authorize(String username, String password) {
    String usernameOrHash = AttributeHashingService.sha256(username);
    String authenticationPrincipal =
        userJpaRepository.findByUsername(usernameOrHash).isPresent() ? usernameOrHash : username;
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(authenticationPrincipal, password));

    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    String token = jwtConfig.generateToken(userDetails);

    Optional<UserEntity> entity =
        userJpaRepository.findByUsername(usernameOrHash).or(() -> userJpaRepository.findByUsername(username));

    if (entity.isEmpty()) {
      throw new DomainException("User not found", USER_NOT_FOUND);
    }

    Optional<AccountEntity> account = accountJpaRepository.findByUserId(entity.get().getId());
    if (account.isEmpty()) {
      throw new DomainException(
          "Account not found for userId=" + entity.get().getId(), ACCOUNT_NOT_FOUND);
    }

    Optional<PersonEntity> person =
        personJpaRepository.findByAccount_AccountId(account.get().getAccountId());
    if (person.isEmpty()) {
      throw new DomainException(
          "Person not found for accountId=" + account.get().getAccountId(), PERSON_NOT_FOUND);
    }

    Optional<OfficerProfileEntity> officerProfile =
        officerProfileJpaRepository.findByPerson_PersonId(person.get().getPersonId());
    if (officerProfile.isEmpty()) {
      throw new DomainException(
          "Officer not found for personId=" + person.get().getPersonId(),
          OFFICER_PROFILE_NOT_FOUND);
    }

    List<String> roles =
        userDetails.getAuthorities().stream()
            .map(authority -> Role.getBySystemAuth(authority.getAuthority()))
            .toList();

    return UserLoginResponse.builder()
        .userId(entity.get().getId())
        .accountId(account.get().getAccountId())
        .personId(person.get().getPersonId())
        .officerId(officerProfile.get().getOfficerId())
        .authorities(roles)
        .token(token)
        .username(entity.get().getUsername())
        .build();
  }
}
