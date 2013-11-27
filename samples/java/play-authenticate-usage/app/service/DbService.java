package service;

import com.feth.play.module.pa.providers.password.UsernamePasswordAuthUser;
import com.feth.play.module.pa.user.AuthUser;
import com.feth.play.module.pa.user.AuthUserIdentity;
import com.typesafe.config.ConfigFactory;
import models.*;

/**
 * @author Andrey Chaschev chaschev@gmail.com
 */
public enum DbService {
    db;

    public UserDbService dbService = "mysql".equals(ConfigFactory.load().getString("demo.useDatabase")) ? new EbeanUserDbService() : null;

    public boolean existsByAuthUserIdentity(AuthUserIdentity identity) {
        return dbService.existsByAuthUserIdentity(identity);
    }

    public User findByUsernamePasswordIdentity(UsernamePasswordAuthUser identity) {
        return dbService.findByUsernamePasswordIdentity(identity);
    }

    public void setLastLoginDate(AuthUser knownUser) {
        dbService.setLastLoginDate(knownUser);
    }

    public void verify(User unverified) {
        dbService.verify(unverified);
    }

    public void save(LinkedAccount account) {
        dbService.save(account);
    }

    public void deleteByUser(User u, TokenAction.Type type) {
        dbService.deleteByUser(u, type);
    }

    public void addLinkedAccount(AuthUser oldUser, AuthUser newUser) {
        dbService.addLinkedAccount(oldUser, newUser);
    }

    public void save(User user) {
        dbService.save(user);
    }

    public User findByEmail(String email) {
        return dbService.findByEmail(email);
    }

    public LinkedAccount getAccountByProvider(String providerKey) {
        return dbService.getAccountByProvider(providerKey);
    }

    public void merge(AuthUser oldUser, AuthUser newUser) {
        dbService.merge(oldUser, newUser);
    }

    public TokenAction findByToken(String token, TokenAction.Type type) {
        return dbService.findByToken(token, type);
    }

    public User findByAuthUserIdentity(AuthUserIdentity identity) {
        return dbService.findByAuthUserIdentity(identity);
    }

    public void save(TokenAction user) {
        dbService.save(user);
    }

    public void deepSave(User user) {
        dbService.deepSave(user);
    }

    public SecurityRole findByRoleName(String roleName) {
        return dbService.findByRoleName(roleName);
    }

    public void save(SecurityRole role) {
        dbService.save(role);
    }

    public int countRoles() {
        return dbService.countRoles();
    }
}
