package idv.ccw.jdbc;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.util.Assert;

public class JdbcTests {

    private final String roleUser = "ROLE_USER";

    @Test
    public void testAuthenticate() throws Exception {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/spring-security-test");
        dataSource.setUsername("root");
        dataSource.setPassword("root");

        JdbcDaoImpl userDetailsService = new JdbcDaoImpl();
        userDetailsService.setDataSource(dataSource);
        userDetailsService.setEnableAuthorities(true);
        userDetailsService.setEnableGroups(false);

        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(userDetailsService);
        AuthenticationProvider provider = daoProvider;

        AuthenticationManager manager = new ProviderManager(Arrays.asList(provider));
        Authentication userToken = new UsernamePasswordAuthenticationToken("user1","pass");
        Authentication auth = manager.authenticate(userToken);

        User user = (User)auth.getPrincipal();
        boolean isUserInRoleUser = false;
        for (GrantedAuthority grantedAuthority : user.getAuthorities()) {
            if (roleUser.equals(grantedAuthority.getAuthority())) {
                isUserInRoleUser = true;
                break;
            }
        }

        Assert.isTrue(isUserInRoleUser, "role " + roleUser  + " does not exist");
    }
}