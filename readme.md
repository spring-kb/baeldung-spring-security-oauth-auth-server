Spring Security OAuth Authorization Server
==========================================
*Source: https://www.baeldung.com/spring-security-oauth-auth-server*

1\. Introduction
----------------

[OAuth](https://oauth.net/) is an open standard that describes a process of authorization. It can be used to authorize user access to an API. For example, a REST API can restrict access to only registered users with a proper role.

An OAuth authorization server is responsible for authenticating the users and issuing access tokens containing the user data and proper access policies.

In this tutorial, we’ll implement a simple OAuth application using the [Spring Security OAuth Authorization Server](https://github.com/spring-projects/spring-authorization-server#spring-authorization-server) project.

In the process, we’ll create a client-server application that will fetch a list of Baeldung articles from a REST API. Both the client services and server services will require an OAuth authentication.

2\. Authorization Server Implementation
---------------------------------------

We’ll start by looking at the OAuth authorization server configuration. It’ll serve as an authentication source for both the article resource and client servers.

freestar.config.enabled\_slots.push({ placementName: "baeldung\_leaderboard\_mid\_1", slotId: "baeldung\_leaderboard\_mid\_1" });

### 2.1. Dependencies

First, we’ll need to add a few dependencies to our _pom.xml_ file:

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
        <version>3.2.2</version>
    </dependency>

### 2.2. Configuration

First, we’ll create an _application.yml_ file to specify the port that our auth server will run on by setting the _server.port_ property:

    server:
      port: 9000

Next, since each authorization server needs to have a unique issuer URL, we’ll set ours up with a localhost alias of _http://auth-server_ on port _9000_ by setting the _spring.security.oauth2.authorizationserver.issuer_ property:

    spring:
      security:
        oauth2:
          authorizationserver:
            issuer: http://auth-server:9000

In addition, we’ll add an entry “_127.0.0.1 auth-server_” in our _/etc/hosts_ file. This allows us to run the client and the auth server on our local machine and avoids problems with session cookie overwrites between the two.

Finally, we’ll configure the repository of client services. In our example, we’ll have a single client named _articles-client_:

freestar.config.enabled\_slots.push({ placementName: "baeldung\_leaderboard\_mid\_2", slotId: "baeldung\_leaderboard\_mid\_2" });

    spring:
      security:
        oauth2:
          authorizationserver:
            client:
              articles-client:
                registration:
                  client-id: articles-client
                  client-secret: "{noop}secret"
                  client-name: Articles Client
                  client-authentication-methods:
                    - client_secret_basic
                  authorization-grant-types:
                    - authorization_code
                    - refresh_token
                  redirect-uris:
                    - http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc
                    - http://127.0.0.1:8080/authorized
                  scopes:
                    - openid
                    - articles.read

The properties we’re configuring are:

*   Client ID – Spring will use it to identify which client is trying to access the resource
*   Client secret code – a secret known to the client and server that provides trust between the two
*   Authentication method – in our case, we’ll use basic authentication, which is just a username and password
*   Authorization grant type – we want to allow the client to generate both an authorization code and a refresh token
*   Redirect URI – the client will use it in a redirect-based flow
*   Scope – this parameter defines authorizations that the client may have. In our case, we’ll have the required _OidcScopes.OPENID_ and our custom one, articles. read

Then we can move to the Spring Beans configuration. First, we’ll enable the Spring web security module with a _@Configuration and_ an _@EnableWebSecurity_ annotated configuration class:

    @Configuration
    @EnableWebSecurity
    public class DefaultSecurityConfig {
        // ...
    }

Next, we’ll configure a Spring Security filter chain to apply the default OAuth security and generate a default form login page:

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
          .oidc(withDefaults()); // Enable OpenID Connect 1.0
        return http.formLogin(withDefaults()).build();
    }

Then we’ll configure the second Spring Security filter chain for authentication:

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest()
              .authenticated())
          .formLogin(withDefaults());
        return http.build();
    }

Here we’re calling _authorizeRequests.anyRequest().authenticated()_ to require authentication for all requests. We’re also providing a form-based authentication by invoking the _formLogin(defaults())_ method.

freestar.config.enabled\_slots.push({ placementName: "baeldung\_leaderboard\_mid\_3", slotId: "baeldung\_leaderboard\_mid\_3" });

Finally, we’ll define a set of example users that we’ll use for testing. For the sake of this example, we’ll create a repository with just a single admin user:

    @Bean
    UserDetailsService users() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.builder()
          .username("admin")
          .password("password")
          .passwordEncoder(encoder::encode)
          .roles("USER")
          .build();
        return new InMemoryUserDetailsManager(user);
    }

3\. Resource Server
-------------------

Now we’ll create a resource server that will return a list of articles from a GET endpoint. The endpoints should allow only requests that are authenticated against our OAuth server.

### 3.1. Dependencies

First, we’ll include the required dependencies:

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        <version>3.2.2</version>
    </dependency>

### 3.2. Configuration

Before we start with the implementation code, we should configure some properties in the _application.yml_ file. The first one is the server port:

    server:
      port: 8090

Next, it’s time for the security configuration. We need to set up the proper URL for our authentication server with the host and the port we’ve configured in the _ProviderSettings_ bean earlier:

    spring:
      security:
        oauth2:
          resourceserver:
            jwt:
              issuer-uri: http://auth-server:9000

Now we can set up our web security configuration. Again, we want to explicitly state that every request to article resources should be authorized and have the proper _articles.read_ authority:

    @Configuration
    @EnableWebSecurity
    public class ResourceServerConfig {
    
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.securityMatcher("/articles/**")
              .authorizeHttpRequests(authorize -> authorize.anyRequest()
                .hasAuthority("SCOPE_articles.read"))
              .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
            return http.build();
        }
    }

As shown here, we’re also invoking the _oauth2ResourceServer()_ method, which will configure the OAuth server connection based on the _application.yml_ configuration.

### 3.3. Articles Controller

Finally, we’ll create a REST controller that will return a list of articles under the _GET /articles_ endpoint:

freestar.config.enabled\_slots.push({ placementName: "baeldung\_incontent\_1", slotId: "baeldung\_incontent\_1" });

    @RestController
    public class ArticlesController {
    
        @GetMapping("/articles")
        public String[] getArticles() {
            return new String[] { "Article 1", "Article 2", "Article 3" };
        }
    }

4\. API Client
--------------

For the last part, we’ll create a REST API client that will fetch the list of articles from the resource server.

### 4.1. Dependencies

To start, we’ll include the necessary dependencies:

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
        <version>3.2.2</version>
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-webflux</artifactId>
        <version>6.1.3</version>
    </dependency>
    <dependency>
        <groupId>io.projectreactor.netty</groupId>
        <artifactId>reactor-netty</artifactId>
        <version>1.1.15</version>
    </dependency>
    

### 4.2. Configuration

As we did earlier, we’ll define some configuration properties for authentication purposes:

    server:
      port: 8080
    
    spring:
      security:
        oauth2:
          client:
            registration:
              articles-client-oidc:
                provider: spring
                client-id: articles-client
                client-secret: secret
                authorization-grant-type: authorization_code
                redirect-uri: "http://127.0.0.1:8080/login/oauth2/code/{registrationId}"
                scope: openid
                client-name: articles-client-oidc
              articles-client-authorization-code:
                provider: spring
                client-id: articles-client
                client-secret: secret
                authorization-grant-type: authorization_code
                redirect-uri: "http://127.0.0.1:8080/authorized"
                scope: articles.read
                client-name: articles-client-authorization-code
            provider:
              spring:
                issuer-uri: http://auth-server:9000

Now we’ll create a _WebClient_ instance to perform HTTP requests to our resource server. We’ll use the standard implementation with just one addition of the OAuth authorization filter:

    @Bean
    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
          new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        return WebClient.builder()
          .apply(oauth2Client.oauth2Configuration())
          .build();
    }

The _WebClient_ requires an _OAuth2AuthorizedClientManager_ as a dependency. Let’s create a default implementation:

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
    
        OAuth2AuthorizedClientProvider authorizedClientProvider =
          OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .build();
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
          clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
    
        return authorizedClientManager;
    }

Lastly, we’ll configure web security:

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {
    
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
              .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
              )
              .oauth2Login(oauth2Login ->
                oauth2Login.loginPage("/oauth2/authorization/articles-client-oidc"))
              .oauth2Client(withDefaults());
            return http.build();
        }
    }

Here, as well as in other servers, we’ll need every request to be authenticated. Additionally, we need to configure the login page URL (defined in _.yml_ config) and the OAuth client.

### 4.3. Articles Client Controller

Finally, we can create the data access controller. We’ll use the previously configured _WebClient_ to send an HTTP request to our resource server:

freestar.config.enabled\_slots.push({ placementName: "baeldung\_incontent\_2", slotId: "baeldung\_incontent\_2" });

    @RestController
    public class ArticlesController {
    
        private WebClient webClient;
    
        @GetMapping(value = "/articles")
        public String[] getArticles(
          @RegisteredOAuth2AuthorizedClient("articles-client-authorization-code") OAuth2AuthorizedClient authorizedClient
        ) {
            return this.webClient
              .get()
              .uri("http://127.0.0.1:8090/articles")
              .attributes(oauth2AuthorizedClient(authorizedClient))
              .retrieve()
              .bodyToMono(String[].class)
              .block();
        }
    }

In the above example, we’re taking the OAuth authorization token from the request in a form of _OAuth2AuthorizedClient_ class. It’s automatically bound by Spring using the _@RegisterdOAuth2AuthorizedClient_ annotation with proper identification. In our case, it’s pulled from the _article-client-authorizaiton-code_ that we configured previously in the _.yml_ file.

This authorization token is further passed to the HTTP request.

### 4.4. Accessing the Articles List

Now when we go into the browser and try to access the _http://127.0.0.1:8080/articles_ page, we’ll be automatically redirected to the OAuth server login page under _http://auth-server:9000/login_ URL:

[![loginPage](/wp-content/uploads/2021/03/loginPage.png)](/wp-content/uploads/2021/03/loginPage.png)
----------------------------------------------------------------------------------------------------

After providing the proper username and password, the authorization server will redirect us back to the requested URL, the list of articles.

Further requests to the articles endpoint won’t require logging in, as the access token will be stored in a cookie.

5\. Conclusion
--------------

In this article, we learned how to set up, configure, and use the Spring Security OAuth Authorization Server.

As always, the full source code is available [over on GitHub](https://github.com/Baeldung/spring-security-oauth/tree/master/oauth-authorization-server).