package ru.kata.spring.boot_security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.demo.model.User;



@Repository
public interface UserRepoImpl extends JpaRepository<User,Long> {
    @Query("select u from User u where u.username = :userName")
    User findByUsername(@Param("userName") String userName);
}
