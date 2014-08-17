/******************************************************************
 * File:        MemUserStore.java
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.util.ByteSource;


/**
 * Non-persistent memory implementation of a UserSore for testing use.
 * Can initialize this from a file with syntax:
 * <pre>
 * user http://id/user1 "name1"  password1
 * user http://id/user2 "name2"  password2
 *
 * http://id/user1 Manager:/reg1
 * http://id/user2 GrantAdmin
 *
 * </pre>
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class MemUserStore extends BaseUserStore implements UserStore {
    protected Map<String, UserRecord> users = new HashMap<String, UserRecord>();
    protected Map<String, Set<String>> permissions = new HashMap<String, Set<String>>();

    protected boolean initstore() {
        return true;
    }

    protected void startTransaction() {}
    protected void commit() {}

    @Override
    public boolean doRegister(UserInfo user) {
        if (users.containsKey(user.getId())) {
            return false;
        }
        UserRecord record = new UserRecord(user.getId(), user.getName());
        record.initSalt();
        users.put(record.id, record);
        return true;
    }

    @Override
    protected UserRecord getRecord(String id) {
        return users.get(id);
    }

    @Override
    public Set<String> getPermissions(String id) {
        Set<String> auth = new HashSet<>();
        safeAdd(auth, permissions.get(id) );
        safeAdd(auth, permissions.get(AUTH_USER_ID) );
        return auth;
    }
    
    private void safeAdd(Set<String> set, Set<String> additions) {
        if (additions != null) {
            set.addAll(additions);
        }
    }

    @Override
    public void doAddPermision(String id, String permission) {
        Set<String> auth = permissions.get(id);
        if (auth == null) {
            auth = new HashSet<String>();
            permissions.put(id, auth);
        }
        auth.add(permission);
    }

    @Override
    public void doRemovePermission(String id, String path) {
        Set<String> perms = permissions.get(id);
        List<String> toRemove = new ArrayList<String>();
        for (String p : perms) {
            if ( AppRealm.permissionPath(p).equals(path) ) {
                toRemove.add(p);
            }
        }
        perms.removeAll(toRemove);
    }

    @Override
    public void doUnregister(String id) {
        users.remove(id);
    }

    @Override
    public void doSetCredentials(String id, ByteSource credentials, int minstolive) {
        users.get(id).setPassword(credentials, minstolive);
    }

    @Override
    public void doRemoveCredentials(String id) {
        users.get(id).clearPassword();
    }

    @Override
    public List<UserPermission> authorizedOn(String path) {
        List<UserPermission> matches = new ArrayList<UserPermission>();
        for (String id : permissions.keySet()) {
            Set<String> perms = permissions.get(id);
            for (String p : perms) {
                String[] parts = p.split(":");
                String paction = parts[0];
                String ppath = parts[1];
                if (ppath.equals(path) || ppath.equals("*")) {
                    UserInfo user = new UserInfo(id, users.get(id).name); 
                    matches.add( new UserPermission(user, paction) );
                }
            }
        }
        return matches;
    }

    @Override
    public List<UserInfo> listUsers(String match) {
        List<UserInfo> matches = new ArrayList<UserInfo>();
        for (UserRecord record : users.values()) {
            if (record.name.contains(match)) {
                matches.add( new UserInfo(record.id, record.name) );
            }
        }
        return matches;
    }

}
