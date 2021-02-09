package com.example.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecurity.security.enums.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
             new ApplicationUser(
                     "asad",
                     passwordEncoder.encode("password"),
                     STUDENT.getGrantedAuthority(),
                     true,
                     true,
                     true,
                     true

             ),
            new ApplicationUser(
                    "mark",
                    passwordEncoder.encode("password"),
                    ADMIN.getGrantedAuthority(),
                    true,
                    true,
                    true,
                    true

            ),
            new ApplicationUser(
                    "john",
                    passwordEncoder.encode("password"),
                    ADMIN_TRAINEE.getGrantedAuthority(),
                    true,
                    true,
                    true,
                    true

            )
        );
        return applicationUsers;
    }
}