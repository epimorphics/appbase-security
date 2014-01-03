/******************************************************************
 * File:        UserStore.java
 * Created by:  Dave Reynolds
 * Created on:  2 Apr 2013
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

import java.util.List;
import java.util.Set;

import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.util.ByteSource;

/**
 * Interface abstraction for the store of registered users. The actual
 * user credentials are not stored since we rely on OpenID for that.
 * Stores permissions of the form "{action}:{target}" using the Shiro
 * WildcardPermission syntax but this interface works at the level of strings.
 *
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public interface UserStore {

    /** ID of a pseudo user which stores the global permissions available to anyone logged in */
    public static final String AUTH_USER_ID = "http://localhost/anon";

    /**
     * Link this store to a specific authorization realm
     */
    public void setRealm(AppRealm realm);

    /**
     * Register a new user.
     * Return true if the new registration succeeded, false if the user is already registered.
     */
    public boolean register(UserInfo user);

    /**
     * Test if a user is registered. Returns their user information and credentials
     * if they are or null if not registered. Stored and returned credentials are salt-hashed
     * to make it easy to allow user defined passwords in the future, redundant for
     * generated passwords. If the user has no credentials or they have timed out then
     * the credentials will be null.
     *
     * @param id the openid identifier string authenticated by the user
     */
    public SaltedAuthenticationInfo checkUser(String id);

    /**
     * Unregister a user, removing them and any permissions from the store
     */
    public void unregister(String id);

    /**
     * Store new credentials for the user
     *
     * @param id the openid identifier string authenticated by the user
     * @param credentials the password to store
     * @param minstolive the time-to-livefor the credentials in minutes
     */
    public void setCredentials(String id, ByteSource credentials, int minstolive);

    /**
     * Create a new random password, set it and return it.
     * <p>
     * Yes, the return ought to be a char[] to allow for reseting but the
     * use case will be creating string serializations of the key in any case
     * to send it out so the added security of using char[] is zero.</p>
     */
    public String createCredentials(String id, int minstolive);

    /**
     * Remove the credentials for the user
     */
    public void removeCredentials(String id);


    /**
     * Return all the permissions and rolefor this user
     */
    public Set<String> getPermissions(String id);

    /**
     * Record a new permission for this user.
     */
    public void addPermision(String id, String permission);

    /**
     * Remove permissions from this user for the given path.
     */
    public void removePermission(String id, String target);

    /**
     * Return the set of users who have some explicit permission over the given path
     */
    public List<UserPermission> authorizedOn(String target);

    /**
     * Return the set of users whose name includes the given string
     */
    public List<UserInfo> listUsers(String match);


}
