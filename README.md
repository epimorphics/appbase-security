appbase-security
================

Shiro-based security layer for appbase projects.

   * Provides UserStore for holding registered users and associated permissions, optionally including password credentials. Includes a database-backed store based on embedded Derby and a memory based implementation which is loaded from a configuration file.
   * Provides a Realm implementation which has an associated UserStore and allows authentication tokens which are externally validated.
   * Permissions structure is based on Shiro Wildcard permissions but assumes a simplified pattern of "{action}:{location}". Permissions can be retrieved by location as well as by user.
   * Provides packaged access to an OpenID implementation so it's easy to create applications where you can register and login using OpenID such as Google.      

## Usage

Can use any Shiro configuration method and register an instance of AppBaseRealm with an associated UserStore. 

The normal way to do this in a web app is to include Shiro in the web.xml and provide a shiro.ini file to customize the Shiro set up. To get access to the UserStore it can be preferable to create the UserStore as part of appbase config and then reference that from the shiro.ini. This is the approach outlined below.

### Set up web.xml

There are three web.xml configuration directives needed to set up shiro.

Define a filter to enable shiro-based control of page accesses (optional):

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

Set a listener to startup the shiro environment on webapp start up. Put this after the appbase listener:

    <listener>
      <listener-class>org.apache.shiro.web.env.EnvironmentLoaderListener</listener-class>
    </listener>


### Shiro configuration

Typical Shiro configuration goes in WEB-INF/shiro.ini

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
    # The 'urls' section is used for url-based securityin web applications. 

This configures the appbase Realm and attaches a user credentials store which is found as the appbase component called "userstore".

The [users] and [roles] sections aren't used.

### User store configuration

In the WEB-INF/app.conf file create and configure an appropriate UserStore. 

For a Derby database store then use something like:

    userstore            = com.epimorphics.appbase.security.DBUserStore
    userstore.initfile   = {webapp}/WEB-INF/user.ini
    userstore.dbfile     = /var/opt/ldregistry/dcutil/userstore
    userstore.systemHome = /var/opt/ldregistry/dcutil/

The `dbfile` parameter gives the location where the database will be stored. The `systemHome` parameter is home the home directory where Derby will put things like log files. 

For a memory base store use:

    userstore            = com.epimorphics.appbase.security.MemUserStore
    userstore.initfile   = {webapp}/WEB-INF/user.ini

The `initfile` parameter gives optional initial user credentials information. The layout of this file is described below.

### UserStore ini file

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
    
## OpenID, login and registration

The Login class provides a set of convenience methods to enable user registration and login via OpenID, login via password credentials and logout.

To use this you need to provide a set of URL endpoints which invoke the various actions and handle OpenID reponse processing. The easy way to do this via Jersey. For example:

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
            OpenidRequest oid = new OpenidRequest(uriInfo.getBaseUri().toString() + "system/security/response");
            oid.setProvider(provider);
            oid.setReturnURL(returnURL);
            try {
                processOpenID(request, response, oid);
            }  catch (Exception e) {
                throw new WebApiException(Status.BAD_REQUEST, "Login/registration action failed: " + e);
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
            OpenidRequest oid = new OpenidRequest(uriInfo.getBaseUri().toString() + "system/security/response");
            oid.setProvider(provider);
            oid.setReturnURL(returnURL);
            oid.setRegister(true);
            try {
                processOpenID(request, response, oid);
            }  catch (Exception e) {
                throw new WebApiException(Status.BAD_REQUEST, "Login/registration action failed: " + e);
            }
            return Response.ok().build();
        }
    
        // Logout the current loged in user
        @Path("/logout")
        @POST
        public void doLogout(@Context HttpServletRequest request, @Context HttpServletResponse response) throws IOException {
            logout(request);
            response.sendRedirect(request.getServletContext().getContextPath());
        }
    
        // Internal endpoint use in the OpenID handshake
        @Path("/response")
        @GET
        public Response openIDResponse(@Context HttpServletRequest request, @Context HttpServletResponse response) {
            try {
                UserStore userstore = AppConfig.getApp().getComponentAs("userstore", UserStore.class);
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
            VelocityRender velocity =  AppConfig.getApp().getComponentAs("velocity", VelocityRender.class);
            StreamingOutput out =  velocity.render("error.vm", uriInfo.getPath(), context, uriInfo.getQueryParameters(), "message", message);
            return Response.status(Status.BAD_REQUEST).entity(out).build();
        }
    }
```

## Other

The UserStore implementation also provides various methods for accessing available permissions and users and for creating time-limited password credentials. See the source code for details.

