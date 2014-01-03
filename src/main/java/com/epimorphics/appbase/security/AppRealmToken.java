/******************************************************************
 * File:        RegToken.java
 * Created by:  Dave Reynolds
 * Created on:  4 Apr 2013
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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * Authentication tokens used for the AppRealm. Allows for a
 * "verified" flag to enable the OpenID authentication to create
 * pre-verified tokens. An OpenID token will have empty password
 * credentials but isVerified will return true. A password
 * token used for API access will have password credentials but
 * will not be verified. In all cases the "username" will be
 * the OpenID identifier for the subject.
 *
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class AppRealmToken extends UsernamePasswordToken implements AuthenticationToken {
    private static final long serialVersionUID = 797348172301182843L;

    protected boolean verified;

    /**
     * Construct an OpenID token with an empty password.
     */
    public AppRealmToken(String id, boolean isVerified) {
        super(id, "");
        verified = isVerified;
    }

    /**
     * Construct a token with password-style credentials
     */
    public AppRealmToken(String id, String password) {
        super(id, password);
        verified = false;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

}
