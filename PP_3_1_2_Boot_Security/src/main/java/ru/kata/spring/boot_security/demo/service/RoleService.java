package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.repository.RoleRepoImpl;

import java.util.List;

@Service
public class RoleService {
    private final RoleRepoImpl roleRepo;
    @Autowired
    public RoleService(RoleRepoImpl roleRepo) {
        this.roleRepo = roleRepo;
    }

    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }

    public void newRole(Role role) {
        roleRepo.save(role);
    }
}
