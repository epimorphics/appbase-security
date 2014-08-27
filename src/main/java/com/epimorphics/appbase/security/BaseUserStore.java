/******************************************************************
 * File:        BaseUserStore.java
 * Created by:  Dave Reynolds
 * Created on:  7 Apr 2013
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.epimorphics.appbase.core.ComponentBase;
import com.epimorphics.util.EpiException;

/**
 * Support for loading a new store from a bootstrap file.
 *
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public abstract class BaseUserStore extends ComponentBase implements UserStore {
    static final Logger log = LoggerFactory.getLogger( BaseUserStore.class );
    public static final String DEFAULT_ALGORITHM = "SHA-512";
    public static final int    DEFAULT_ITERATIONS = 1;
    
    protected SecureRandomNumberGenerator rand = new SecureRandomNumberGenerator();
    protected File initfile = null;
    protected AppRealm realm;
    
    public void setInitfile(String file) {
        initfile = asFile(file);
    }
    
    @Override
    public void setRealm(AppRealm realm) {
        this.realm = realm;
        // Can only initialize the store once we know the realm
        checkStore();
    }

    private void checkStore() {
        if ( !initstore() ) return;
        if (initfile == null) return;
        loadStore();
    }
    
    /**
     * Test if store is available, if not create a new empty
     * store and return true.
     */
    protected abstract boolean initstore();

    /**
     * Start a transaction if the store supports transactions
     */
    protected abstract void startTransaction();

    /**
     * Commit the transaction if the store supports transactions
     */
    protected abstract void commit();

    /**
     * Return the record for the identified user.
     */
    protected abstract UserRecord getRecord(String id);

    @Override
    public UserInfo getUser(String id) {
        UserRecord record = getRecord(id);
        if (record == null) {
            return null;
        } else {
            return new UserInfo(id, record.getName());
        }
    }
    
    @Override
    public SaltedAuthenticationInfo checkUser(String id) {
        UserRecord record = getRecord(id);
        if (record == null) {
            return null;
        }
        if (System.currentTimeMillis() < record.timeout) {
            return new SimpleAuthenticationInfo(
                    new UserInfo(record.id, record.name),
                    record.getPasword(),
                    record.getSalt(),
                    realm.getName());
        } else {
            return new SimpleAuthenticationInfo(
                    new UserInfo(record.id, record.name),
                    null,
                    realm.getName());
        }
    }

    @Override
    public String createCredentials(String id, int minstolive) {
        String password = rand.nextBytes().toHex();
        setCredentials(id, ByteSource.Util.bytes(password), minstolive);
        log.info("Created a new password for user " + id);
        return password;
    }

    // Check that current subject has permission to grant permissions on the given path
    // Subclasses may override this to do actual checking
    protected void checkSubjectControls(String path) {
    }

    private void log(String message) {
        try {
            String user = ((UserInfo)SecurityUtils.getSubject().getPrincipal()).getName();
            log.info(user + " " + message);
        } catch (Exception e) {
            log.info("Bootstrap " + message);
        }
    }

    private void clearCache(String id) {
        realm.clearCacheFor(id);
    }

    @Override
    public boolean register(UserInfo user) {
        boolean success = doRegister(user);
        if (success) {
            log("Registered user " + user.getId() + " (" + user.getName() + ")");
        }
        clearCache(user.getId());
        return success;
    }
    public abstract boolean doRegister(UserInfo user);

    @Override
    public void unregister(String id) {
        doUnregister(id);
        clearCache(id);
        log("Removed registration for " + id);
    }
    public abstract void doUnregister(String id);

    @Override
    public void setCredentials(String id, ByteSource credentials, int minstolive) {
        doSetCredentials(id, credentials, minstolive);
        clearCache(id);
        log("Registered a password for user " + id);
    }
    public abstract void doSetCredentials(String id, ByteSource credentials, int minstolive);

    @Override
    public void removeCredentials(String id) {
        doRemoveCredentials(id);
        clearCache(id);
        log("Cleared password for user " + id);
    }
    public abstract void doRemoveCredentials(String id);

    @Override
    public void addPermision(String id, String permission) {
        checkSubjectControls( AppRealm.permissionPath(permission) ); 
        doAddPermision(id, permission);
        clearCache(id);
        log("Added permission " + permission + " for user " + id);
    }
    public abstract void doAddPermision(String id, String permission);

    @Override
    public void removePermissionsOn(String id, String path) {
        checkSubjectControls(path);
        doRemovePermissionsOn(id, path);
        clearCache(id);
        log("Removed permissions for user " + id + " on path " + path);
    }
    public abstract void doRemovePermissionsOn(String id, String path);

    @Override
    public void removePermission(String id, String permission) {
        checkSubjectControls( AppRealm.permissionPath(permission) ); 
        doRemovePermission(id, permission);
        clearCache(id);
        log("Removed permission " + permission + " for user " + id);
    }
    public abstract void doRemovePermission(String id, String permission);

    private void loadStore() {
        if (initfile == null)  {
            // no preload
            return;
        }
        startTransaction();
        BufferedReader in = null;
        try {
            in = new BufferedReader(new FileReader(initfile));
            String line = null;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (line.startsWith("user")) {
                    Matcher patternMatch = USER_LINE_PATTERN.matcher(line);
                    if (patternMatch.matches()) {
                        String id = patternMatch.group(1);
                        UserInfo user = new UserInfo(id, patternMatch.group(2));
                        register(user);
                        String password = patternMatch.group(3);
                        if (password != null && !password.isEmpty()) {
                            setCredentials(id,  ByteSource.Util.bytes(password), Integer.MAX_VALUE);
                        }
                    } else {
                        throw new EpiException("Could not parse user declaration: " + line);
                    }
                } else {
                    String[] parts = line.split("\\s+");
                    if (parts.length != 2) {
                        throw new EpiException("Permissions line had wrong number of components: " + line);
                    }
                    String id = parts[0];
                    String perm = parts[1];
                    addPermision(id, perm);
                }
            }
            log.info("Load user store from " + initfile);
        } catch (Exception e) {
            log.error("Failed to load UserStore initialization file: " + initfile + " ", e);
        } finally {
            commit();
            try {
                in.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    static final Pattern USER_LINE_PATTERN = Pattern.compile("user\\s+([^\\s]+)\\s+\"([^\"]+)\"\\s*([^\\s]*)");


class UserRecord {
    protected String id;
    protected String name;
    protected String salt;
    protected String password;
    protected long timeout;
    protected String role;

    public UserRecord(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public void initSalt() {
        salt = rand.nextBytes().toHex();
    }

    public ByteSource getPasword() {
        if (password != null) {
            return ByteSource.Util.bytes( Hex.decode(password) );
        } else {
            return null;
        }
    }
    
    public String getName() {
        return name;
    }

    public String getID() {
        return id;
    }
    
    public ByteSource getSalt() {
        return ByteSource.Util.bytes( Hex.decode(salt) );
    }

    public void setPassword(ByteSource password, long minstolive) {
        timeout = System.currentTimeMillis() + minstolive * 60 * 1000;
        HashRequest request = new HashRequest.Builder()
            .setSource(password)
            .setSalt( getSalt() )
            .build();
        Hash hash = realm.getHashService().computeHash(request);
        this.password = hash.toHex();
    }

    public void clearPassword() {
        password = null;
        timeout = 0;
    }
}

}
