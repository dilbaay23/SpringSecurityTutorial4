package com.moon.springbootsecurity.auth;

import java.util.Optional;

/**
 * Created by Moon on 12/11/2020
 */
public interface ApplicationUserDAO {
     Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
