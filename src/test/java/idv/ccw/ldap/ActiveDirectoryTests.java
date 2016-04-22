package idv.ccw.ldap;

import java.util.Arrays;

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
        AuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("mytest.com",
                "ldap://192.168.0.1:389");
        Authentication userToken = new UsernamePasswordAuthenticationToken("username", "password");
        AuthenticationManager manager = new ProviderManager(Arrays.asList(provider));
        manager.authenticate(userToken);
    }
}