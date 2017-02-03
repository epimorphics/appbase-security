appbase-security
================

[Shiro](https://shiro.apache.org/)-based security layer for [AppBase](https://github.com/epimorphics/appbase) projects.

   * Provides a `UserStore` for holding registered users and associated permissions, optionally including password credentials. Includes a database-backed store based on embedded [Derby](https://db.apache.org/derby/) and a memory based implementation which is loaded from a configuration file.
   * Provides a Realm implementation which has an associated `UserStore` and allows authentication tokens which are externally validated.
   * Permissions structure is based on Shiro Wildcard permissions but assumes a simplified pattern of `"{action}:{location}"`. Permissions can be retrieved by location as well as by user.
   * Provides packaged access to an [OpenID](http://openid.net/) implementation so it's easy to create applications where you can register and login using OpenID such as Google.

## Usage

We can use any Shiro configuration method and register an instance of `AppBaseRealm` with an associated `UserStore`.

The normal way to do this in a web app is to include Shiro in the `web.xml` and provide a `shiro.ini` file to customize the Shiro set up. To get access to the `UserStore` it can be preferable to create the `UserStore` as part of appbase config and then reference that from the `shiro.ini`. This is the approach outlined below.

### Set up web.xml

There are three `web.xml` configuration directives needed to set up Shiro.

_(Optional)_ Define a filter to enable Shiro-based control of page accesses:

```xml
<filter>
  <filter-name>ShiroFilter</filter-name>
  <filter-class>org.apache.shiro.web.servlet.ShiroFilter</filter-class>
</filter>

<filter-mapping>
  <filter-name>ShiroFilter</filter-name>
  <url-pattern>/*</url-pattern>
  <dispatcher>REQUEST</dispatcher>
  <dispatcher>FORWARD</dispatcher>
  <dispatcher>INCLUDE</dispatcher>
  <dispatcher>ERROR</dispatcher>
</filter-mapping>
```

Set a listener to startup the Shiro environment on webapp start up. Put this after the appbase listener:

```xml
<listener>
  <listener-class>org.apache.shiro.web.env.EnvironmentLoaderListener</listener-class>
</listener>
```

### Shiro configuration

Minimal Shiro configuration goes in `WEB-INF/shiro.ini`

```INI
# =======================
# Shiro INI configuration
# =======================

[main]
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
realm = com.epimorphics.appbase.security.AppRealm
realm.discoverUserStore = userstore
realm.authenticationCachingEnabled = true
securityManager.realms = $realm

[users]
[roles]
[urls]
```

This configures the appbase Realm and attaches a user credentials store which is found as the appbase component called `"userstore"`.

The `[users]` and `[roles]` sections aren't used.

For a web application you can also control authentication here, for example:

```INI
# =======================
# Shiro INI configuration
# =======================

[main]
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
realm = com.epimorphics.appbase.security.AppRealm
realm.discoverUserStore = userstore
realm.authenticationCachingEnabled = true
securityManager.realms = $realm

passAuth = org.apache.shiro.web.filter.authc.PassThruAuthenticationFilter
passAuth.loginUrl = /view/login-page

[users]
[roles]

[urls]
/view/login-page = anon
/view/** = passAuth
/api/** = passAuth
/system/security/login = anon
/system/** = passAuth
```

### User store configuration

In the `WEB-INF/app.conf` file, create and configure an appropriate `UserStore`.

For a Derby database store, use something like:

```INI
userstore            = com.epimorphics.appbase.security.DBUserStore
userstore.initfile   = {webapp}/WEB-INF/user.ini
userstore.dbfile     = /var/opt/ldregistry/dcutil/userstore
userstore.systemHome = /var/opt/ldregistry/dcutil/
```

The `dbfile` parameter gives the location where the database will be stored. The `systemHome` parameter is home the home directory where Derby will put things like log files.

For an in-memory store, use:

```INI
userstore            = com.epimorphics.appbase.security.MemUserStore
userstore.initfile   = {webapp}/WEB-INF/user.ini
```

The `initfile` parameter gives optional initial user credentials information. The layout of this file is described below.

### UserStore ini file

The user store, whether memory based or full DB, can be preloaded from an initialization file.
By convention, this is `user.ini`.

The `user.ini` file comprises a set of declarations, one per line. Lines beginning with `#` are comment lines.

User registration entries start with the user keyword and take the form:

```INI
user  openid  "name"
```

or

```INI
user  id  "name"   password
```

For example:

```INI
user https://profiles.google.com/1147194443288764760228 "Alice"
user dave@epimorphics.com "Dave Reynolds" shouldbechanged
```

An OpenID profile for anyone with a Google account can be obtained from their profile or
Google-plus home page and copying the long number from there into the above URL pattern.
A general Google login generates an OpenID which depends on the requesting web site
as well as the user. To determine the ID in that case start the bootstrap registry,
register the target user and note the resulting OpenID, then shutdown the registry
and modify the initialization file accordingly.

There is a built-in anonymous user with pseudo OpenID of `http://localhost/anon`.
It is convenient to declare that user in the initialization file as well, so as to bind a
visible name to that id. For example:

    user http://localhost/anon "Any authenticated"

The second type of declaration line is used to grant permissions to a user. These take the form:

    id permission

Where the *permission* takes the form:

    action:target

Each part (*action* or *target*) can be a comma-separated list of values or a wildcard (*).

For example:

    http://localhost/anon Read:*

## Password login and registration

Provide a set of API endpoints for login, logout and any required user management. For example:

```java
@Path("login")
@POST
public Response login(
        @FormParam("userid") String userid,
        @FormParam("password") String password,
        @FormParam("rememberMe") boolean rememberMe,
        @FormParam("redirectURL") String redirectURL) {
    if (Login.passwordLogin(userid, password, rememberMe)) {
        log.info("User " + userid + " logged in");
        if (validator != null) {
            validator.successfulLogin(userid);
        }
        return redirectTo(redirectURL);
    } else {
        return redirectToView("login-page?error=Login+credentials+failed");
    }
}

@Path("logout")
@POST
public Response logout() {
    Subject subject = SecurityUtils.getSubject();
    log.info("User " + subject.getPrincipal() + " logged out");
    subject.logout();
    return redirectToView("index");
}
```

## Security violations

To check permissions in API endpoints, use the Shiro utilities. A convenient
pattern is the throw an exception if a security restriction is violated and
then use a mapper to catch the exception and render a message.

For example, to perform the checks you might use something like:

```java
public void checkAllowed(String permission) {
    Subject subject = SecurityUtils.getSubject();
    if ( ! subject.isPermitted(permission) ) {
        throw new SecurityViolationException(permission, (UserInfo) subject.getPrincipal());
    }
}
```

Then, somewhere visible to Jersey, declare a mapper:

```java
@Provider
public class SecurityViolationMapper  implements
        ExceptionMapper<SecurityViolationException> {
    static final Logger log = LoggerFactory.getLogger( SecurityViolationMapper.class );

    @Override
    public Response toResponse(SecurityViolationException exception) {
        String permission = exception.getPermission();
        log.warn( String.format(
                    "User %s blocked attempting action requiring permission %s",
                    exception.getUser(), permission) );

        String message = "You do not have permission to " + permission;
        String location = PubUtil.get().getViewBase() +
                          "/error?message=" + NameUtils.encodeSafeName(message);
        try {
            URI locationURI = new URI(location);
            return Response.seeOther(locationURI).build();
        } catch (URISyntaxException e) {
            log.error("Internal error reporting security violation", e);
            return null;
        }
    }
}
```

## OpenID, login and registration

The `Login` class provides a set of convenience methods to enable user registration
and login via OpenID, login via password credentials and logout.

To use this you need to provide a set of URL endpoints which invoke the various actions
and handle OpenID response processing. The easy way to do this is via
[Jersey](https://jersey.java.net/index.html). For example:

```java
@Path("/system/security")
public class LoginCmds {
    protected @Context UriInfo uriInfo;
    protected @Context ServletContext context;

    // request OpenID login for a registered user
    @Path("/login")
    @POST
    public Response login(
            @FormParam("provider") String provider,
            @FormParam("return") String returnURL,
            @Context HttpServletRequest request,
            @Context HttpServletResponse response) {
        OpenidRequest oid = new OpenidRequest(uriInfo.getBaseUri().toString() + 
                                              "system/security/response");
        oid.setProvider(provider);
        oid.setReturnURL(returnURL);
        try {
            processOpenID(request, response, oid);
        }  catch (Exception e) {
            throw new WebApiException(Status.BAD_REQUEST, 
                                      "Login/registration action failed: " + e);
        }
        return Response.ok().build();
    }

    // Register a new user via OpenID
    @Path("/register")
    @POST
    public Response register(
            @FormParam("provider") String provider,
            @FormParam("return") String returnURL,
            @Context HttpServletRequest request,
            @Context HttpServletResponse response) {
        OpenidRequest oid = new OpenidRequest(uriInfo.getBaseUri().toString() + 
                                              "system/security/response");
        oid.setProvider(provider);
        oid.setReturnURL(returnURL);
        oid.setRegister(true);
        try {
            processOpenID(request, response, oid);
        }  catch (Exception e) {
            throw new WebApiException(Status.BAD_REQUEST, 
                                      "Login/registration action failed: " + e);
        }
        return Response.ok().build();
    }

    // Logout the current loged in user
    @Path("/logout")
    @POST
    public void doLogout(@Context HttpServletRequest request, 
                         @Context HttpServletResponse response) throws IOException {
        logout(request);
        response.sendRedirect(request.getServletContext().getContextPath());
    }

    // Internal endpoint use in the OpenID handshake
    @Path("/response")
    @GET
    public Response openIDResponse(@Context HttpServletRequest request, 
                                   @Context HttpServletResponse response) {
        try {
            UserStore userstore = AppConfig.getApp()
                                           .getComponentAs("userstore", UserStore.class);
            return redirectTo( verifyResponse(request, response, userstore) );
        } catch (Exception e) {
            return renderError( e.getMessage() );
        }
    }

    private Response redirectTo(String path) {
        URI uri;
        try {
            uri = new URI(path);
            return Response.seeOther(uri).build();
        } catch (URISyntaxException e) {
            throw new EpiException(e);
        }
    }

    // Some means to report login errors, this assumes AppBase velocity rendering using a generic error.vm template
    private Response renderError(String message) {
        VelocityRender velocity =  AppConfig.getApp()
                                            .getComponentAs("velocity", VelocityRender.class);
        StreamingOutput out =  velocity.render("error.vm", 
                                               uriInfo.getPath(), 
                                               context, 
                                               uriInfo.getQueryParameters(), 
                                               "message", message);
        return Response.status(Status.BAD_REQUEST).entity(out).build();
    }
}
```

## Other

The `UserStore` implementation also provides various methods for accessing available
permissions and users and for creating time-limited password credentials.
See the source code for details.

