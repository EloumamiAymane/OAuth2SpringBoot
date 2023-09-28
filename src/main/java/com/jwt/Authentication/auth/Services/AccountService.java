package com.jwt.Authentication.auth.Services;

import com.jwt.Authentication.auth.Entity.AppRole;
import com.jwt.Authentication.auth.Entity.AppUser;
import com.jwt.Authentication.auth.Repository.AppRoleRepository;
import com.jwt.Authentication.auth.Repository.AppUserRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;

    public AccountService(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
    }

    public AppUser newUser(AppUser appUser){
        return appUserRepository.save(appUser);
    }
    public AppRole newRole(AppRole appRole){
        return appRoleRepository.save(appRole);
    }
    public void addRoleToUser(String userName,String roleName){
        AppUser appUser=appUserRepository.findByUsername(userName);
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }
    public AppUser findByUserName(String userName){
        return appUserRepository.findByUsername(userName);
    }
}
