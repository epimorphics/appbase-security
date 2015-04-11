/******************************************************************
 * File:        LoginValidator.java
 * Created by:  Dave Reynolds
 * Created on:  11 Apr 2015
 * 
 * (c) Copyright 2015, Epimorphics Limited
 *
 *****************************************************************/

package com.epimorphics.appbase.security;

import java.util.HashMap;
import java.util.Map;

import com.epimorphics.appbase.core.AppConfig;
import com.epimorphics.appbase.core.ComponentBase;
import static java.lang.Character.*;

/**
 * Utility used to validate passwords and login attempts.
 */
public class LoginValidator extends ComponentBase {
    protected long retriesAllowed = 3;
    protected long retriesDelay = 10 * 60 * 1000;
    protected long passwordCharGroups = 3;
    protected long passwordLength = 8;

    protected Map<String, LoginRecord> logins = new HashMap<String, LoginValidator.LoginRecord>();
    
    /**
     * Return the configured login validator, may be null if no validation is configured
     */
    public static LoginValidator getValidator() {
        return AppConfig.getApp().getA(LoginValidator.class);
    }
    
    public synchronized boolean tryAllowed(String userid) {
        LoginRecord record = logins.get(userid);
        if (record == null) {
            record = new LoginRecord();
            logins.put(userid, record);
        }
        return record.tryAllowed();
    }
    
    public synchronized void successfulLogin(String userid) {
        logins.remove(userid);
    }
    
    public boolean isAcceptablePassword(String passwd) {
        if (passwd.length() < passwordLength) return false;
        boolean hasLowerAlpha = false;
        boolean hasUpperAlpha = false;
        boolean hasNumeric = false;
        boolean hasSymbol = false;
        int nclasses = 0;
        for (int i = 0; i < passwd.length(); i++) {
            char c = passwd.charAt(i);
            if (isLetter(c) && isLowerCase(c)) {
                if (!hasLowerAlpha) {
                    hasLowerAlpha = true;
                    nclasses++;
                }
            } else if (isLetter(c) && isUpperCase(c)) {
                if (!hasUpperAlpha) {
                    hasUpperAlpha = true;
                    nclasses++;
                }
            } else if (isDigit(c)) {
                if (!hasNumeric) {
                    hasNumeric = true;
                    nclasses++;
                }
            } else {
                if (!hasSymbol){
                    hasSymbol = true;
                    nclasses++;
                }
            }
        }
        if (nclasses < passwordCharGroups) {
            return false;
        }
        return false;
    }
    
    public void setRetriesAllowed(long retriesAllowed) {
        this.retriesAllowed = retriesAllowed;
    }

    public void setRetriesDelay(long retriesDelay) {
        this.retriesDelay = retriesDelay;
    }

    public void setPasswordCharGroups(long passwordCharGroups) {
        this.passwordCharGroups = passwordCharGroups;
    }

    public void setPasswordLength(long passwordLength) {
        this.passwordLength = passwordLength;
    }


    public class LoginRecord {
        protected int retryCount = 0;
        protected long timeout = 0;      // Set to expiry time if locked
        
        public LoginRecord() {
        }
        
        public boolean tryAllowed() {
            if (timeout > 0) {
                if (timeout < System.currentTimeMillis()) {
                    // Currently locked
                    return false;
                } else {
                    // Lock expired
                    timeout = 0;
                    retryCount = 0;
                    return true;
                }
            } else {
                retryCount ++;
                if (retryCount > retriesAllowed) {
                    // Too many tries, set lock
                    timeout = System.currentTimeMillis() + retriesDelay;
                    return false;
                }
            }
            return true;
        }
        
        public void resetCount() {
            timeout = 0;
            retryCount = 0;
        }
    }

}
