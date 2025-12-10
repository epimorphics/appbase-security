/******************************************************************
 * File:        TestMemUserStore.java
 * Created by:  Dave Reynolds
 * Created on:  3 Jan 2014
 * 
 * (c) Copyright 2014, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.util.ByteSource;
import org.junit.jupiter.api.Test;

import com.epimorphics.appbase.security.BaseUserStore.UserRecord;

public class TestUserStores {
    static final String ALICE_ID = "http://example.com/alice";
    static final String ALICE_NAME = "Alice tester";

    static final String BOB_ID = "http://example.com/bob";
    static final String BOB_NAME = "Bob";

    UserInfo Alice = new UserInfo(ALICE_ID, ALICE_NAME);
    UserInfo Bob   = new UserInfo(BOB_ID, BOB_NAME);
    
    @Test
    public void testMemStore() {
        MemUserStore store = new MemUserStore();
        AppRealm realm = new AppRealm();
        realm.setUserStore(store);
        
        store.register(Alice);
        store.addPermision(ALICE_ID, "Read:project1");
        store.addPermision(ALICE_ID, "Write:project2");
        store.register(Bob);
        store.addPermision(BOB_ID, "Read:*");
        store.addPermision(BOB_ID, "*:project3");
        
        doCredentialsTest(store);
        doPermissionsTest(store);
        doStoreSearchTest(store);
    }
    
    @Test
    public void testMemInitFile() {
        MemUserStore store = new MemUserStore();
        store.setInitfile("test/user.ini");
        AppRealm realm = new AppRealm();
        realm.setUserStore(store);
        
        doCredentialsTest(store);
        doPermissionsTest(store);
        doStoreSearchTest(store);
    }
    
    @Test
    public void testDBStore() {
        DBUserStore store = new DBUserStore();
        store.setDbfile("memory:test");
        store.setInitfile("test/user.ini");
        AppRealm realm = new AppRealm();
        realm.setUserStore(store);
        
        doCredentialsTest(store);
        doPermissionsTest(store);
        doStoreSearchTest(store);
        store.shutdown();
    }
    
    // Experimental test
    @Test
    public void testMultiLevelPermissions() {
        DBUserStore store = new DBUserStore();
        store.setDbfile("memory:test");
        store.setInitfile("test/user2.ini");
        AppRealm realm = new AppRealm();
        realm.setUserStore(store);

        store.addPermision(ALICE_ID, "domain:update:foo");
        assertTrue( store.getPermissions(ALICE_ID).contains("domain:update:foo") );
        
        store.shutdown();
    }
    
    static protected void doCredentialsTest(BaseUserStore store) {
        SaltedAuthenticationInfo info = store.checkUser(ALICE_ID);
        assertEquals(ALICE_NAME, ((UserInfo)info.getPrincipals().getPrimaryPrincipal()).getName());

        // Check credentials management
        UserRecord record = store.getRecord(ALICE_ID);
        record.setPassword(ByteSource.Util.bytes("my password"), 10);
        String expectedPassword = record.password;
        store.setCredentials(ALICE_ID, ByteSource.Util.bytes("my password"), 10);
        record = store.getRecord(ALICE_ID);
        assertNotNull(record.getPasword());
        assertEquals(expectedPassword, record.password);

        store.removeCredentials(ALICE_ID);
        record = store.getRecord(ALICE_ID);
        assertNull(record.getPasword());

        store.setCredentials(ALICE_ID, ByteSource.Util.bytes("my password"), 0);
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            // ignore
        }
        info = store.checkUser(ALICE_ID);
        String password = (String) info.getCredentials();
        assertTrue(password == null || password.isEmpty());
    }
    
    static protected void doPermissionsTest(UserStore store) {
        Set<String> permissions = store.getPermissions(ALICE_ID);
        assertTrue(permissions.contains("Read:project1"));
        assertTrue(permissions.contains("Write:project2"));
        
        List<UserPermission> perms = store.authorizedOn("project2");
        assertEquals(2, perms.size());
        UserPermission p = perms.get(0);
        assertEquals (p.getUser().getId().equals(ALICE_ID) ? "Write" : "Read", p.getPermissions());
        p = perms.get(1);
        assertEquals (p.getUser().getId().equals(ALICE_ID) ? "Write" : "Read", p.getPermissions());
        
        store.removePermissionsOn(BOB_ID, "*");
        perms = store.authorizedOn("project2");
        assertEquals(1, perms.size());
        p = perms.get(0);
        assertEquals (ALICE_ID, p.getUser().getId());
        assertEquals ("Write", p.getPermissions());
        
        store.removePermission(ALICE_ID, "Write:project2");
        permissions = store.getPermissions(ALICE_ID);
        assertTrue(permissions.contains("Read:project1"));
        assertFalse(permissions.contains("Write:project2"));
    }
    
    static protected void doStoreSearchTest(UserStore store) {
        // Check listing users
        store.register( new UserInfo("http://example.com/bob2", "Sponge Bob") );
        store.register( new UserInfo("http://example.com/bob3", "Bob Le Ponge") );
        List<UserInfo> bobs = store.listUsers("Bob");
        assertTrue(bobs.size() == 3);
        assertEquals(BOB_NAME, bobs.get(0).getName());
        assertEquals("Sponge Bob", bobs.get(2).getName());

        // Check removal
        store.unregister(ALICE_ID);
        assertNull( store.checkUser(ALICE_ID) );
    }
}
