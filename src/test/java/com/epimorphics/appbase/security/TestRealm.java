/******************************************************************
 * File:        TestRealm.java
 * Created by:  Dave Reynolds
 * Created on:  3 Jan 2014
 * 
 * (c) Copyright 2014, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;

public class TestRealm {
    
    @Test
    public void testRealmControls() {
        // Set up Shiro from ini file
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("file:test/shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        AppRealm realm = (AppRealm) ((RealmSecurityManager) securityManager).getRealms().iterator().next();

        Subject subject = SecurityUtils.getSubject();
        subject.login( new AppRealmToken(TestUserStores.BOB_ID, true) );
        
        assertEquals(TestUserStores.BOB_ID, ((UserInfo) subject.getPrincipal()).getId());
        assertTrue( subject.isAuthenticated() );
        assertTrue( subject.isPermitted("Read:project1") );
        assertTrue( subject.isPermitted("Read:project2") );
        assertTrue( subject.isPermitted("Write:project3") );
        assertFalse( subject.isPermitted("Write:project1") );
        
        assertTrue( subject.isPermitted("Action:project1:component1") );
        assertTrue( subject.isPermitted("Action:project1:component2") );
        assertTrue( subject.isPermitted("Action:project1:component3") );
        assertTrue( subject.isPermitted("Action:project3:component1") );
        assertTrue( subject.isPermitted("Action:project4:component3") );
        assertFalse( subject.isPermitted("Action:project4:component1") );
        
        // Test login/logout - hard to do as separate method, get interactions between multipple SecurityManager globals
        Login.setPassword(realm, "testpassword", "newpassword");
        subject.logout();
        
        subject.login( new AppRealmToken(TestUserStores.BOB_ID, "newpassword") );
        assertTrue( subject.isAuthenticated() );
        assertFalse( subject.isPermitted("Write:project2") );
        assertTrue( subject.isPermitted("Write:project3") );
        
        Login.resetPassword(realm, TestUserStores.ALICE_ID, "alicepassword");
        subject.logout();
        
        subject.login( new AppRealmToken(TestUserStores.ALICE_ID, "alicepassword") );
        assertTrue( subject.isAuthenticated() );
        assertTrue( subject.isPermitted("Write:project2") );
        assertFalse( subject.isPermitted("Write:project3") );
        
        if (subject != null) subject.logout();
        SecurityUtils.setSecurityManager(null);
    }
}
