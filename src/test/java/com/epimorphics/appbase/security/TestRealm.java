/******************************************************************
 * File:        TestRealm.java
 * Created by:  Dave Reynolds
 * Created on:  3 Jan 2014
 * 
 * (c) Copyright 2014, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.mgt.SecurityManager;
import org.junit.Test;
import static org.junit.Assert.*;

public class TestRealm {

    @Test
    public void testRealmControls() {
        // Set up Shiro from ini file
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("file:test/shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        
        Subject subject = SecurityUtils.getSubject();
        subject.login( new AppRealmToken(TestUserStores.BOB_ID, true) );
        
        assertEquals(TestUserStores.BOB_ID, ((UserInfo) subject.getPrincipal()).getOpenid());
        assertTrue( subject.isAuthenticated() );
        assertTrue( subject.isPermitted("Read:project1") );
        assertTrue( subject.isPermitted("Read:project2") );
        assertTrue( subject.isPermitted("Write:project3") );
        assertFalse( subject.isPermitted("Write:project1") );
        
        subject.logout();
        SecurityUtils.setSecurityManager(null);
    }
}
