package idv.ccw.ldap;

import java.util.ArrayList;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.server.ApacheDSContainer;

import junit.framework.Assert;

/**
 * Active Directory
 * sAMAccountName : username
 * displayName : full name
 * mail : email address
 *
 * ApacheDS
 * uid : username
 * cn : full name
 * mailacceptinggeneralid : email address
 */
public class LdapTests {
    private static final String root = "dc=springframework,dc=org";
    private static final String ldif = "classpath*:*.ldif";
    private static final int port = 53389;//ActiveDirectory:389
    private ApacheDSContainer apacheDsContainer = null;

    @Before
    public void before() throws Exception {
        this.apacheDsContainer = new ApacheDSContainer(root, ldif);
        this.apacheDsContainer.setPort(port);
        this.apacheDsContainer.afterPropertiesSet();
    }

    @After
    public void after() throws Exception {
        if (this.apacheDsContainer != null) {
            this.apacheDsContainer.stop();
        }
    }

    @Test
    public void testAuthentication() throws Exception {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://127.0.0.1:" + String.valueOf(port));
        //contextSource.setUserDn("uid=bob,ou=people,dc=springframework,dc=org");
        //contextSource.setPassword("bobspassword");
        contextSource.afterPropertiesSet();

        String searchBase = "ou=people,dc=springframework,dc=org";
        String searchFilter = "(uid={0})";//ActiveDirectory:sAMAccountName
        LdapUserSearch userSearch = new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource);
        BindAuthenticator bind = new BindAuthenticator(contextSource);
        bind.setUserSearch(userSearch);

        final LdapAuthenticationProvider provider = new LdapAuthenticationProvider(bind);

        AuthenticationManager manager = new ProviderManager(new ArrayList<AuthenticationProvider>() {
            private static final long serialVersionUID = -8980855146895150361L;
            {
                this.add(provider);
            }
        });

        Authentication userToken = new UsernamePasswordAuthenticationToken("javadude", "javadudespassword");
        manager.authenticate(userToken);
    }

    @Test
    public void testLdapTemplateAuthenticate() throws Exception {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://127.0.0.1:" + String.valueOf(port));
        contextSource.afterPropertiesSet();

        LdapTemplate tmpl = new LdapTemplate(contextSource);
        String searchBase = "ou=people,dc=springframework,dc=org";
        EqualsFilter filter = new EqualsFilter("uid", "javadude");
        boolean isAuthenticated = tmpl.authenticate(searchBase, filter.toString(), "javadudespassword");

        Assert.assertTrue("authentication failed", isAuthenticated);
    }
}