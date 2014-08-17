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

import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility functions for registration and login via OpenID.
 * Binding these to resource URIs via jersey in the web application.
 * 
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class Login {
    static final Logger log = LoggerFactory.getLogger( Login.class );

    // Velocity binding names
    public static final String VN_SUBJECT = "subject";

    /**
     * Login using password credentials instead of OpenID.
     * Return true if the login succeeded.
     */
    static public boolean passwordLogin(String userid, String password) {
        try {
            AppRealmToken token = new AppRealmToken(userid, password);
            Subject subject = SecurityUtils.getSubject();
            subject.login(token);
            return true;
        } catch (Exception e) {
            log.warn(String.format("API Login failure for userid %s [%s]: %s", userid, e.getClass().toString(), e.getMessage()));
            return false;
        }
    }

    /**
     * Logout the current user
     */ 
    static public void logout(HttpServletRequest request) throws IOException {
        request.getSession().removeAttribute(VN_SUBJECT);
        SecurityUtils.getSubject().logout();
    }

}
