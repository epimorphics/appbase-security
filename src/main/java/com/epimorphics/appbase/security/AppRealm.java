/******************************************************************
 * File:        AppRealm.java
 * Created by:  Dave Reynolds
 * Created on:  3 Jan 2014
 * 
 * (c) Copyright 2014, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import java.util.Collection;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashService;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

import com.epimorphics.appbase.core.AppConfig;

public class AppRealm extends AuthorizingRealm {
    public static final String DEFAULT_ALGORITHM = "SHA-512";
    public static final int    DEFAULT_ITERATIONS = 100000;

    protected HashService hashService;
    protected UserStore userstore;
    
    public static AppRealm getRealm() {
        Collection<Realm> realms = ((RealmSecurityManager) SecurityUtils.getSecurityManager()).getRealms();
        for (Realm realm : realms) {
            if (realm instanceof AppRealm) {
                return (AppRealm)realm;
            }
        }
        return null;
    }
    
    
    public AppRealm() {
        setCredentialsMatcher( new AppRealmCredentialsMatcher() );
        DefaultHashService hashing = new DefaultHashService();
        hashing.setHashAlgorithmName( DEFAULT_ALGORITHM );
        hashing.setHashIterations( DEFAULT_ITERATIONS );
        hashService = hashing;
    }

    /**
     * Set the number of iterations that the hash service should use.
     * Must be set before any new credentials (including bootstrap ones) are hashed.
     */
    public void setHashIterations(int iterations) {
        ((DefaultHashService) hashService).setHashIterations(iterations);
        ((AppRealmCredentialsMatcher)getCredentialsMatcher()).setHashIterations(iterations);
    }

    /**
     * Configure a user store by looking up its name in the set of configured components
     */
    public void setDiscoverUserStore(String storename) {
        setUserStore( AppConfig.getApp().getComponentAs(storename, UserStore.class) );
    }
    
    /**
     * Configure the user store for this realm
     */
    public void setUserStore(UserStore store) {
        userstore = store;
        store.setRealm(this);
    }
    
    public UserStore getUserStore() {
        return userstore;
    }
    
    /**
     * Return the path part of a action:path permission structure
     */
    static public String permissionPath(String permission) {
        return splitPermission(permission)[1];
    }
    
    /**
     * Return the action part of a action:path permission structure
     */
    static public String permissionAction(String permission) {
        return splitPermission(permission)[0];
    }

    /**
     * The string permission structure allows standard Shiro wildcard structures foo:bar:baz...
     * However, the user store is optimized for a structure action:path where you can add or remove
     * all actions related to a path. This allows for other permission resolvers (e.g. the
     * hierarchical paths supported by the registry). To cater for the mismatch we simply
     * split the first segment of the wildcard to treat as an action and treat the rest
     * as the path. 
     */
    static public String[] splitPermission(String permission) {
        int split = permission.indexOf(":");
        if (split == -1) {
            return new String[]{permission, ""};
        } else {
            return new String[]{
                    permission.substring(0, split),
                    permission.substring(split+1) };
        }
    }
    
    public HashService getHashService() {
        return hashService;
    }

    /**
     * Clear cached authentication and authorization information
     * for an individual. Should be called from UserStore implementation
     * whenever a change is made.
     */
    protected void clearCacheFor(String id) {
        UserInfo principal = new UserInfo(id, null);
        PrincipalCollection pc = new SimplePrincipalCollection(principal, getName());
        clearCache(pc);
        if (id.equals(UserStore.AUTH_USER_ID)) {
            // For the anonymous user have to lose whole cache because this affects every user
            Cache<Object, AuthorizationInfo> cache = getAuthorizationCache();
            if (cache != null) {
                cache.clear();
            }
        }
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken token) throws AuthenticationException {
        if (!(token instanceof AppRealmToken)) {
            if (token instanceof UsernamePasswordToken) {
                UsernamePasswordToken otoken = (UsernamePasswordToken)token;
                token = new AppRealmToken(otoken.getUsername(), otoken.getPassword());
            } else {
                throw new IncorrectCredentialsException();
            }
        }
        AppRealmToken rtoken = (AppRealmToken)token;
        String id = (String)rtoken.getPrincipal();
        SaltedAuthenticationInfo info = userstore.checkUser(id);
        return info;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            PrincipalCollection principals) {
        UserInfo user = (UserInfo)principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo ai = new SimpleAuthorizationInfo();
        ai.setStringPermissions( userstore.getPermissions(user.getId()) );
        return ai;
    }

    // Override implementation so that key used for tokens (openid URI) is also
    // used for princpals (UserInfo)
    @Override
    protected Object getAuthenticationCacheKey(PrincipalCollection pc) {
        return ((UserInfo)pc.getPrimaryPrincipal()).getId();
    }
    
}
