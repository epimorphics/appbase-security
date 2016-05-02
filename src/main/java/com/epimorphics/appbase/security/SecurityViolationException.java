/******************************************************************
 * File:        SecurityViolationException.java
 * Created by:  Dave Reynolds
 * Created on:  1 May 2016
 * 
 * (c) Copyright 2016, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import com.epimorphics.appbase.security.UserInfo;

/**
 * Exception use to signal a problem with the
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class SecurityViolationException extends RuntimeException {
    private static final long serialVersionUID = -3628367907309661615L;

    protected String permission;
    protected UserInfo user;
    
    public SecurityViolationException(String permission, UserInfo user) {
        super("Permission denied for " + permission);
        this.user = user;
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }

    public UserInfo getUser() {
        return user;
    }

    
}
