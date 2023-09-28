package com.jwt.Authentication.auth.Repository;

import com.jwt.Authentication.auth.Entity.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RestController;


@Repository
public interface AppRoleRepository  extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
