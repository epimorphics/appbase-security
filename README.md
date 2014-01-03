appbase-security
================

Shiro-based security layer for appbase projects.

## Usage

## Shiro configuration

## UserStore init

The user store, whether memory based or full DB, can be preloaded from an initialization file (by convension user.ini).

The user.ini file comprises a set of declarations, one per line (lines beginning with # are comment lines).

User registration entries start with the user keyword and take the form:

    user  openid  "name"
    
or    

    user  openid  "name"   password
    
For example:

    user https://profiles.google.com/1147194443288764760228 "Alice"
    
An OpenID profile for anyone with a Google account can be obtained from their profile or Google-plus home page and copying the long number from there into the above URL pattern. A general Google login generates an OpenID which depends on the requesting web site as well as the user. To determine the ID in that case start the bootstrap registry, register the target user and note the resulting OpenID, then shutdown the registry and modify the initialization file accordingly.

There is a built in anonymous user with pseudo OpenID of http://localhost/anon. It is convenient to declare that user in the initialization file as well, so as to bind a visible name to that id. For example:

    user http://localhost/anon "Any authenticated"
    
The second type of declaration line is used to grant permissions to a user. These take the form:

    openid permission
    
Where the *permission* takes the form:

    action:target
    
Each part (*action* or *target*) can be a comma-separated list of values or a wildcard (*).
    
For example:

    http://localhost/anon Read:*