/******************************************************************
 * File:        RegCredentialsMatcher.java
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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;

/**
 * Credentials which checks the token to test if it has already
 * been verified using OpenID.
 *
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class AppRealmCredentialsMatcher extends HashedCredentialsMatcher implements CredentialsMatcher {
    
    public AppRealmCredentialsMatcher() {
        setHashAlgorithmName(AppRealm.DEFAULT_ALGORITHM);
        setHashIterations(AppRealm.DEFAULT_ITERATIONS);
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof AppRealmToken) {
            if (((AppRealmToken)token).isVerified()) return true;
        }
        return super.doCredentialsMatch(token, info);
    }

}
