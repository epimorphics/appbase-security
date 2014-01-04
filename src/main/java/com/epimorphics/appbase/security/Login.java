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
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.epimorphics.util.EpiException;

/**
 * Utility functions for registration and login via OpenID.
 * Binding these to resource URIs via jersey in the web application.
 * 
 * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
 */
public class Login {
    static final Logger log = LoggerFactory.getLogger( Login.class );

    public static final String DEFAULT_PROVIDER = "https://www.google.com/accounts/o8/id";
    public static final String PROVIDER_COOKIE = "appbase-login-provider";

    // Session attribute names
    public static final String SA_OPENID_DISC = "openid_disc";
    public static final String SA_OPENID_PROVIDER = "openid_provider";
    public static final String SA_REGISTRATION = "isRegistration";
    public static final String SA_RETURN_URL = "returnURL";

    // Attribute parameter names
    public static final String AP_EMAIL = "email";
    public static final String AP_FIRST_NAME = "firstName";
    public static final String AP_LAST_NAME = "lastName";
    public static final String AP_FULL_NAME = "fullname";

    // Velocity binding names
    public static final String VN_SUBJECT = "subject";
    public static final String VN_REGISTRATION_STATUS = "registrationStatus";
    public static final String RS_NEW = "new";
    public static final String RS_ALREADY_REGISTERED = "already";
    public static final String RS_LOGIN = "login";

    private static ConsumerManager manager = null;
    static {
        try {
            manager = new ConsumerManager();
        } catch (Exception e) {
            log.error("Failed to initialize openid subsystem", e);
        }
    }


    /**
     * Perform a login or registration via OpenID.
     * @throws EpiException if the request is malformed in some way.
     */
    @SuppressWarnings("rawtypes")
    protected void processOpenID(HttpServletRequest request, HttpServletResponse response, OpenidRequest oid) {
        HttpSession session = request.getSession();
        session.setAttribute(SA_REGISTRATION, oid.isRegister());
        session.setAttribute(SA_OPENID_PROVIDER, oid.getProvider());
        session.setAttribute(SA_RETURN_URL, oid.getReturnURL());

        log.info("Authentication request for " + oid.getProvider() + (oid.isRegister() ? " (registration)" : ""));

        try
        {
            // perform discovery on the user-supplied identifier
            List discoveries = manager.discover(oid.getProvider());

            // attempt to associate with the OpenID provider
            // and retrieve one service endpoint for authentication
            DiscoveryInformation discovered = manager.associate(discoveries);

            // store the discovery information in the user's session
            request.getSession().setAttribute(SA_OPENID_DISC, discovered);

            // obtain a AuthRequest message to be sent to the OpenID provider
            AuthRequest authReq = manager.authenticate(discovered, oid.getResponseURL());

            if (oid.isRegister()) {
                // Attribute Exchange example: fetching the 'email' attribute
                FetchRequest fetch = FetchRequest.createFetchRequest();
                if (oid.getProvider().contains("google.com")) {
//                    fetch.addAttribute(AP_EMAIL, "http://axschema.org/contact/email", false);
                    fetch.addAttribute(AP_FIRST_NAME, "http://axschema.org/namePerson/first", true);
                    fetch.addAttribute(AP_LAST_NAME, "http://axschema.org/namePerson/last", true);
                } else if (oid.getProvider().contains("yahoo.com")) {
//                    fetch.addAttribute(AP_EMAIL, "http://axschema.org/contact/email", false);
                    fetch.addAttribute(AP_FULL_NAME, "http://axschema.org/namePerson", true);
                } else { //works for myOpenID
//                    fetch.addAttribute(AP_EMAIL, "http://schema.openid.net/contact/email", false);
                    fetch.addAttribute(AP_FULL_NAME, "http://schema.openid.net/namePerson", true);
                }

                // attach the extension to the authentication request
                authReq.addExtension(fetch);
            }

            // For version2 endpoints can do a form-redirect but this is easier,
            // Relies on payload being less ~ 2k, currently ~ 800 bytes
            response.sendRedirect(authReq.getDestinationUrl(true));
        }
        catch (Exception e)
        {
            throw new EpiException("Login/registration action failed: " + e);
        }
    }

    /**
     * Process the verification response from the OpenID provider. This should be called
     * from a URL which is given as part of the original OpenIDRequest. If the verification
     * was successful it returns the URL to which the user should be redirected (specified
     * in the original call), otherwise an EpiExpception is thrown.
     */
    @SuppressWarnings({ "unchecked" })
    public String verifyResponse(HttpServletRequest request, HttpServletResponse httpresponse, UserStore userstore) {
        try {
            HttpSession session = request.getSession();

            // extract the parameters from the authentication response
            // (which comes in as a HTTP request from the OpenID provider)
            ParameterList response =
                    new ParameterList(request.getParameterMap());

            // retrieve the previously stored discovery information
            DiscoveryInformation discovered = (DiscoveryInformation)
                    session.getAttribute("openid-disc");

            // extract the receiving URL from the HTTP request
            StringBuffer receivingURL = request.getRequestURL();
            String queryString = request.getQueryString();
            if (queryString != null && queryString.length() > 0)
                receivingURL.append("?").append(request.getQueryString());

            // verify the response; ConsumerManager needs to be the same
            // (static) instance used to place the authentication request
            VerificationResult verification = manager.verify(
                    receivingURL.toString(),
                    response, discovered);

            // examine the verification result and extract the verified identifier
            Identifier verified = verification.getVerifiedId();
            if (verified != null) {
                AuthSuccess authSuccess =  (AuthSuccess) verification.getAuthResponse();
                String name = null;
                if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
                    FetchResponse fetchResp = (FetchResponse) authSuccess
                            .getExtension(AxMessage.OPENID_NS_AX);
                    Map<String, List<String>> attributes = fetchResp.getAttributes();
                    if (attributes.containsKey(AP_FULL_NAME)) {
                        name = attributes.get(AP_FULL_NAME).get(0);
                    } else {
                        name = attributes.get(AP_FIRST_NAME).get(0) + " " + attributes.get(AP_LAST_NAME).get(0);
                    }
                }
                log.info(String.format("Verified identity %s = %s", verified.getIdentifier(), name));
                boolean isRegistration = ((Boolean)session.getAttribute(SA_REGISTRATION)).booleanValue();
                String registrationStatus = RS_LOGIN;
                if (isRegistration) {
                    UserInfo userinfo = new UserInfo(verified.getIdentifier(), name);
                    if (userstore.register( userinfo )) {
                        registrationStatus = RS_NEW;
                    } else {
                        registrationStatus = RS_ALREADY_REGISTERED;
                    }
                }

                AppRealmToken token = new AppRealmToken(verified.getIdentifier(), true);
                Subject subject = SecurityUtils.getSubject();
                try {
                    subject.login(token);
                    session.setAttribute(VN_REGISTRATION_STATUS, registrationStatus);
                    String provider = (String)session.getAttribute(SA_OPENID_PROVIDER);
                    if (provider != null && !provider.isEmpty()) {
                        Cookie cookie = new Cookie(PROVIDER_COOKIE, provider);
                        cookie.setComment("Records the openid provider you last used to log in to a UKGovLD registry");
                        cookie.setMaxAge(60 * 60 * 24 * 30);
                        cookie.setHttpOnly(true);
                        cookie.setPath("/");
                        httpresponse.addCookie(cookie);
                    }
                    return session.getAttribute(SA_RETURN_URL).toString();
                } catch (Exception e) {
                    log.error("Authentication failure: " + e);
                    throw new EpiException("Could not find a registration.");
                }
            }
        } catch (Exception e) {
            throw new EpiException(e);
        }
        throw new EpiException("OpenID login failed");
    }
    
    /**
     * Login using password credentials instead of OpenID.
     * Return true if the login succeeded.
     */
    public boolean passwordLogin(String userid, String password) {
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
    public void logout(HttpServletRequest request) throws IOException {
        request.getSession().removeAttribute(VN_SUBJECT);
        SecurityUtils.getSubject().logout();
    }

    /**
     * Packaged set of parameters for an OpenID login or registration request.
     * 
     * @author <a href="mailto:dave@epimorphics.com">Dave Reynolds</a>
     */
    public class OpenidRequest {
        String provider = DEFAULT_PROVIDER;
        String responseURL;
        String returnURL = "/";
        boolean isRegister = false;
       
        /**
         * Create a login or registration request
         * @param responseURL The URL to use for the OpenID response, this endpoint should invoke a verifyRequest call
         */
        public OpenidRequest(String responseURL) {
            this.responseURL = responseURL;
        }

        /**
         * Set the OpenID provider to use. The default is generic Google login (which is
         * distinct from a person-specific Google profile provider)
         */
        public void setProvider(String provider) {
            this.provider = provider;
        }

        /**
         * Set the URL to which the user will be redirected after a successful login
         */
        public void setReturnURL(String returnURL) {
            this.returnURL = returnURL;
        }

        /**
         * Set to true if this is a registration rather than a login (default is login)
         */
        public void setRegister(boolean isRegister) {
            this.isRegister = isRegister;
        }

        public String getProvider() {
            return provider;
        }

        public String getResponseURL() {
            return responseURL;
        }

        public String getReturnURL() {
            return returnURL;
        }

        public boolean isRegister() {
            return isRegister;
        }
        
        
       
    }
}
