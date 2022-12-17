package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepoImpl;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;
    private final RoleService roleService;
    private final UserRepoImpl userRepoImpl;

    @Autowired
    public AdminController(UserService userService, RoleService roleService,
                           UserRepoImpl userRepoImpl) {
        this.userService = userService;
        this.roleService = roleService;
        this.userRepoImpl = userRepoImpl;
    }

//    @GetMapping
//    private String getAllUsers(Model model) {
//        model.addAttribute("users", userService.getAllUsers());
//        return "admin";
//    }

    @GetMapping
    private String getAllUsers(Principal principal, Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("admin", userService.findUserByUserName(principal.getName()));
        model.addAttribute("newUser", new User());
        model.addAttribute("roles", roleService.getAllRoles());
        return "admin";
    }

//    @GetMapping("/user_new")
//    public String saveUserPage(@ModelAttribute("user") User user, Model model) {
//        List<Role> roles = roleService.getAllRoles();
//        model.addAttribute("roles", roles);
//        return "user_new";
//    }

    @PostMapping
    public String saveUser(@ModelAttribute("user")User user) {
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @DeleteMapping("/{id}")
    public String deleteById(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

//    @GetMapping("/{id}/user_update")
//    public String updateUserPage(@PathVariable("id") Long id, Model model) {
//        List<Role> roles = roleService.getAllRoles();
//        model.addAttribute("user", userService.findBiId(id));
//        model.addAttribute("roles", roles);
//        return "user_update";
//    }
    @PatchMapping("/{id}")
    public String updateUser(@ModelAttribute("user") User user) {
        userService.saveUser(user);
        return "redirect:/admin";
    }

    /////tests


}
