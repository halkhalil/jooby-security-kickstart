package org.jooby.kickstart;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java8.util.function.Predicate;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static java.time.Month.AUGUST;
import static java8.util.stream.StreamSupport.stream;

public final class AppAuthentication implements Authenticator<UsernamePasswordCredentials> {
  private static final Logger log = LoggerFactory.getLogger(AppAuthentication.class);
  private static final String USERNAME = "username";
  private static final String PASSWORD = "password";

  private final List<Map<String, Object>> users;

  public AppAuthentication() {
    this.users = ImmutableList.<Map<String, Object>>builder()
      .add(ImmutableMap.<String, Object>builder()
        .put("username", "luke")
        .put("password", "skywalker")
        .put("birthdate", LocalDate.of(1979, AUGUST, 6))
        .build())
      .add(ImmutableMap.<String, Object>builder()
        .put("username", "anakin")
        .put("password", "darthvader")
        .put("birthdate", LocalDate.of(2001, AUGUST, 26))
        .build())
      .build();
  }

  @Override
  public void validate(UsernamePasswordCredentials credentials, WebContext context) throws HttpAction {
    stream(users)
      .filter(forValid(credentials))
      .findFirst()
      .map(this::asProfile)
      .ifPresent(credentials::setUserProfile);

    if (!stream(users).anyMatch(withUsername(credentials))) throw new CredentialsException("Username not found");
  }

  private Predicate<Map<String, Object>> withUsername(final UsernamePasswordCredentials credentials) {
    return user -> user.get(USERNAME).equals(credentials.getUsername());
  }

  private Predicate<Map<String, Object>> forValid(final UsernamePasswordCredentials credentials) {
    final String username = credentials.getUsername();
    final String password = credentials.getPassword();

    return user -> user.get(USERNAME).equals(username) && user.get(PASSWORD).equals(password);
  }

  private CommonProfile asProfile(final Map<String, Object> user) {
    final CommonProfile profile = new CommonProfile();
    profile.addAttributes(user);
    return profile;
  }
}
