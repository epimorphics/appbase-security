/******************************************************************
* File:        Login.java
 * Created by:  Dave Reynolds
 * Created on:  1 Apr 2013
 *
 * (c) Copyright 2013, Epimorphics Limited
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import java.io.IOException;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.epimorphics.util.EpiException;

/**
 * Utility functions for registration and login via OpenID.
 * Binding these to resource URIs via jersey in the web application.
 * 
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class Login {
    static final Logger log = LoggerFactory.getLogger( Login.class );

    // Action permission required to reset someones password
    public static final String ADMIN_ACTION = "Admin";

    /**
     * Login using password credentials instead of OpenID.
     * Return true if the login succeeded.
     */
    static public boolean passwordLogin(String userid, String password, boolean rememberMe) {
        try {
            AppRealmToken token = new AppRealmToken(userid, password);
            token.setRememberMe(rememberMe);
            Subject subject = SecurityUtils.getSubject();
            subject.login(token);
            return true;
        } catch (Exception e) {
            log.warn(String.format("API Login failure for userid %s [%s]: %s", userid, e.getClass().toString(), e.getMessage()));
            return false;
        }
    }

    static public void setPassword(AppRealm realm, String currentPassword, String newPassword) {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            throw new EpiException("You must be logged in to reset your password");
        }
        if (newPassword == null || newPassword.isEmpty()) {
            throw new EpiException("Must give a new password");
        }
        String userid = ((UserInfo)subject.getPrincipal()).getId();
        try {
            // Check current password in case left screen optn
            AppRealmToken token = new AppRealmToken(userid, currentPassword);
            subject.login(token);

            // Now set the password
            realm.getUserStore().setCredentials(userid, ByteSource.Util.bytes(newPassword), Integer.MAX_VALUE);
            log.info("Changed password for user " + userid);
        } catch (Exception e) {
            log.warn(String.format("Failed to change password for userid %s [%s]: %s", userid, e.getClass().toString(), e.getMessage()));
            throw e;
        }
    }

    static public void resetPassword(AppRealm realm, String userid, String newPassword) {
        if (userid == null || userid.isEmpty() || newPassword == null || newPassword.isEmpty()) {
            throw new EpiException("Must give a user and a new password");
        }
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated() && subject.isPermitted(ADMIN_ACTION)) {
            try {
                realm.getUserStore().setCredentials(userid, ByteSource.Util.bytes(newPassword), Integer.MAX_VALUE);
                log.info("Administrator " + subject.getPrincipal() + " changed password for user " + userid);
            } catch (Exception e) {
                log.warn(String.format("Administrator failed to change password for userid %s [%s]: %s", userid, e.getClass().toString(), e.getMessage()));
                throw e;
            }
        } else {
            log.warn(String.format("Non-administrator %s attempted to change password for userid %s", subject.getPrincipal(), userid));
            throw new EpiException("Must be an administrator to reset a password");
        }
    }
    
    static public void registerUser(AppRealm realm, String userid, String password, String name) { 
        if (userid == null || userid.isEmpty() || password == null || password.isEmpty() || name == null || name.isEmpty()) {
            throw new EpiException( "You must supply all of a username, display name and password to register" );
        }
        UserStore userstore = realm.getUserStore();
        UserInfo userinfo = new UserInfo(userid, name);
        if (userstore.register( userinfo )) {
                userstore.setCredentials(userid, ByteSource.Util.bytes(password), Integer.MAX_VALUE);
        } else {
            log.warn(String.format("User %s tried to register an already registered user, %s", SecurityUtils.getSubject().getPrincipal(), userid));
            throw new EpiException( "That username is already registered" );
        }
    }

    
    /**
     * Logout the current user
     */ 
    static public void logout() throws IOException {
        SecurityUtils.getSubject().logout();
    }

}
