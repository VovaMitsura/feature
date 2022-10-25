package com.example.auth2.config;

import com.example.auth2.model.User;
import com.example.auth2.model.User.UserRole;
import com.example.auth2.repo.UserRepository;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Autowired
  public JwtUserDetailsService(UserRepository userRepository, PasswordEncoder bcryptEncoder) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {

    Optional<User> optionalUser = userRepository.findByEmail(userEmail);
    User user = null;

    if (optionalUser.isEmpty()) {
      user = new User(userEmail, UserRole.CANDIDATE);
    }else
      user = optionalUser.get();

    return new SimpleUserPrincipal(user);
  }
}
