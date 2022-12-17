package ru.kata.spring.boot_security.demo.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.annotation.PostConstruct;
import java.util.*;

//@Component
public class Util {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserService userService;
    private final RoleService roleService;
    public Util(BCryptPasswordEncoder bCryptPasswordEncoder, UserService userService, RoleService roleService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userService = userService;
        this.roleService = roleService;
    }
    @PostConstruct
    public void init() {
        Role roleAdmin = new Role("ROLE_ADMIN");
        Role roleUser = new Role("ROLE_USER");
        List<Role> adminSet = new ArrayList<>();
        List<Role> userSet = new ArrayList<>();
        roleService.newRole(roleAdmin);
        roleService.newRole(roleUser);
        adminSet.add(roleAdmin);
        adminSet.add(roleUser);
        userSet.add(roleUser);
        User admin = new User("Azat", 1992, "pass" , adminSet);
        User user = new User("SampleUser", 1990,"password", userSet);
        userService.saveUser(admin);
        userService.saveUser(user);
    }
}
