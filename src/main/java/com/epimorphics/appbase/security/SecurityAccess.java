/******************************************************************
 * File:        SecurityAccess.java
 * Created by:  Dave Reynolds
 * Created on:  2 May 2016
 * 
 * (c) Copyright 2016, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;

import com.epimorphics.appbase.core.ComponentBase;
import com.epimorphics.appbase.security.AppRealm;
import com.epimorphics.appbase.security.UserInfo;

/**
 * Component to support access to the security features
 */
public class SecurityAccess extends ComponentBase {

    public Subject getSubject() {
        return SecurityUtils.getSubject();
    }
    
    public List<UserInfo> listUsers() {
        return AppRealm.getRealm().getUserStore().listUsers("");
    }
    
    public boolean checkPermission(UserInfo user, String permission) {
        AppRealm realm = AppRealm.getRealm();
        PrincipalCollection pc = new SimplePrincipalCollection(user, realm.getName());
        try {
            realm.checkPermission(pc, permission);
            return true;
        } catch (AuthorizationException e) {
            return false;
        }
    }
}
