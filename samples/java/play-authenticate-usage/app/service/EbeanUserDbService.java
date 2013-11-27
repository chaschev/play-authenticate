package service;

import com.avaje.ebean.Ebean;
import com.avaje.ebean.ExpressionList;
import com.avaje.ebean.QueryIterator;
import com.feth.play.module.pa.providers.password.UsernamePasswordAuthUser;
import com.feth.play.module.pa.user.AuthUser;
import com.feth.play.module.pa.user.AuthUserIdentity;
import models.*;
import play.db.ebean.Model;

/**
 * @author Andrey Chaschev chaschev@gmail.com
 */
public class EbeanUserDbService extends UserDbService {
    public static final Model.Finder<Long, User> find = new Model.Finder<Long, User>(
            Long.class, User.class);


    @Override
    public boolean existsByAuthUserIdentity(AuthUserIdentity identity) {
        final ExpressionList<User> exp;
        if (identity instanceof UsernamePasswordAuthUser) {
            exp = getUsernamePasswordAuthUserFind((UsernamePasswordAuthUser) identity);
        } else {
            exp = getAuthUserFind(identity);
        }
        return exp.findRowCount() > 0;
    }

    @Override
    public User findByAuthUserIdentity(AuthUserIdentity identity) {
        if (identity == null) {
            return null;
        }
        if (identity instanceof UsernamePasswordAuthUser) {
            return findByUsernamePasswordIdentity((UsernamePasswordAuthUser) identity);
        } else {
            return getAuthUserFind(identity).findUnique();
        }
    }

    @Override
    public User findByUsernamePasswordIdentity(UsernamePasswordAuthUser identity) {
        return getUsernamePasswordAuthUserFind(identity).findUnique();
    }

    @Override
    public void merge(AuthUser oldUser, AuthUser newUser) {
        findByAuthUserIdentity(oldUser).merge(
                findByAuthUserIdentity(newUser));
    }

    @Override
    public void save(User user) {
        user.save();
    }

    @Override
    public void deepSave(User user) {
        user.save();
        user.saveManyToManyAssociations("roles");
    }

    @Override
    public void save(TokenAction action) {
        action.save();
    }

    @Override
    public void save(LinkedAccount account) {
        account.save();
    }

    @Override
    public User findByEmail(String email) {
        return getEmailUserFind(email).findUnique();
    }

    @Override
    public LinkedAccount getAccountByProvider(String providerKey) {
        throw new UnsupportedOperationException("todo EbeanUserDbService.getAccountByProvider");
    }

    public static final Model.Finder<Long, SecurityRole> roleFind = new Model.Finder<Long, SecurityRole>(
            Long.class, SecurityRole.class);

    @Override
    public SecurityRole findByRoleName(String roleName) {
        return roleFind.where().eq("roleName", roleName).findUnique();
    }

    @Override
    public void save(SecurityRole role) {
        role.save();
    }

    @Override
    public int countRoles() {
        return roleFind.findRowCount();
    }

    public static final Model.Finder<Long, TokenAction> tokenFind = new Model.Finder<Long, TokenAction>(
            Long.class, TokenAction.class);

    @Override
    public TokenAction findByToken(String token, TokenAction.Type type) {
        return tokenFind.where().eq("token", token).eq("type", type).findUnique();
    }

    @Override
    public void deleteByUser(User u, TokenAction.Type type) {
        QueryIterator<TokenAction> iterator = tokenFind.where()
                .eq("targetUser.id", u.id).eq("type", type).findIterate();
        Ebean.delete(iterator);
        iterator.close();
    }

    private static ExpressionList<User> getAuthUserFind(
            final AuthUserIdentity identity) {
        return find.where().eq("active", true)
                .eq("linkedAccounts.providerUserId", identity.getId())
                .eq("linkedAccounts.providerKey", identity.getProvider());
    }

    private static ExpressionList<User> getUsernamePasswordAuthUserFind(
            final UsernamePasswordAuthUser identity) {
        return getEmailUserFind(identity.getEmail()).eq(
                "linkedAccounts.providerKey", identity.getProvider());
    }

    private static ExpressionList<User> getEmailUserFind(final String email) {
        return find.where().eq("active", true).eq("email", email);
    }

}
