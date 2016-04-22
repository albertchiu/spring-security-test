package idv.ccw.ldap;

import java.util.ArrayList;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

public class ActiveDirectoryTests {
    @Test
    public void testAuthentication() throws Exception {
        final AuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("mytest.com",
                "ldap://192.168.0.1:389");

        Authentication userToken = new UsernamePasswordAuthenticationToken("username", "password");
        AuthenticationManager manager = new ProviderManager(new ArrayList<AuthenticationProvider>() {
            private static final long serialVersionUID = -8980855146895150361L;
            {
                this.add(provider);
            }
        });

        manager.authenticate(userToken);
    }
}