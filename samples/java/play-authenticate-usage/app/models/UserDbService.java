package models;

import com.feth.play.module.pa.providers.password.UsernamePasswordAuthUser;
import com.feth.play.module.pa.user.AuthUser;
import com.feth.play.module.pa.user.AuthUserIdentity;

import java.util.Date;

/**
 * @author Andrey Chaschev chaschev@gmail.com
 */
public abstract class UserDbService {
    public abstract boolean existsByAuthUserIdentity(final AuthUserIdentity identity) ;
    public abstract User findByAuthUserIdentity(final AuthUserIdentity identity);
    public abstract User findByUsernamePasswordIdentity(final UsernamePasswordAuthUser identity);
    public abstract void merge(final AuthUser oldUser, final AuthUser newUser);

    public abstract void save(User user);
    public abstract void deepSave(User user);
    public abstract void save(TokenAction user);

    public abstract void save(LinkedAccount account);

    public abstract User findByEmail(final String email);
    public abstract LinkedAccount getAccountByProvider(final String providerKey);

    public abstract TokenAction findByToken(final String token, final TokenAction.Type type);
    public abstract void deleteByUser(final User u, final TokenAction.Type type);

    public void addLinkedAccount(final AuthUser oldUser, final AuthUser newUser) {
        final User u = findByAuthUserIdentity(oldUser);
        save(u);
    }

    public void setLastLoginDate(final AuthUser knownUser) {
        final User u = findByAuthUserIdentity(knownUser);
        u.lastLogin = new Date();
        save(u);
    }

    public void verify(final User unverified){
        unverified.emailValidated = true;
        save(unverified);
        deleteByUser(unverified, TokenAction.Type.EMAIL_VERIFICATION);
    }

    public abstract SecurityRole findByRoleName(String roleName);

    public abstract void save(SecurityRole role);

    public abstract int countRoles();
}


