```
package hello;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	/**
     * 该方法定义 url 的访问权限，登录路径，注销
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()  //任何人(包括没有经过验证的)都可以访问"/"和"/home"
                // .antMatchers("/admin/**").hasRole("ADMIN")  // "/admin/"开头的URL必须要是管理员用户，譬如”admin”用户
                .anyRequest().authenticated()  //所有其他的 URL 都需要用户进行验证
                .and()
            .formLogin()   //使用 Java 配置默认值设置了基于表单的验证。使用POST提交到"/login"时，需要用"username"和"password"进行验证
                .loginPage("/login")   //指定在需要登录时将用户发送到的URL
                .permitAll()   //用户可以访问 formLogin() 相关的任何URL
                .and()
            .logout()    //注销
                .permitAll();   //用户可以访问 logout() 相关的任何URL。


        //post请求默认的都开启了csrf(跨站请求伪造)的模式，所有post请求都必须带有token之类的验证信息才可以进入登陆页面，这边是禁用csrf模式
        //http.csrf().disable();

        //表示所有的get请求都不需要权限认证
        //http.authorizeRequests().antMatchers(HttpMethod.GET).access("permitAll");

        //对/hello 进行匹配，不管HTTP METHOD是什么
        //http.authorizeRequests().antMatchers("/v1/hello").hasRole("USER");

        //匹配/hello，且http method是POST，需要权限认证
        //http.authorizeRequests().antMatchers(HttpMethod.POST, "/v1/world").hasRole("USER");

        //匹配 /hello，且http method是GET，不需要权限认证
        //http.authorizeRequests().antMatchers(HttpMethod.GET, "/v1/hello").access("permitAll");

        //匹配/admin，并且http method不管是什么，需要admin权限
        //http.authorizeRequests().antMatchers("/v1/admin").hasRole("ADMIN");

        //我们平时写的authenticated，指的是上面配置没有匹配到的url都需要权限认证，但是不管是什么权限，不管是USER，GUEST，ADMIN都可以
        //http.authorizeRequests().anyRequest().authenticated();

        //参数中type等于1的就不做权限认证,
        // 当访问的url地址为http://localhost:8001/web/v1/hello?type=1，因为type值是1，所以匹配
        //http.authorizeRequests().requestMatchers((RequestMatcher) request -> "1".equals(request.getParameter("type"))).access("permitAll");

        //任何html类型的文件都可以访问
        //http.authorizeRequests().antMatchers("/**/*.html").access("permitAll");
    }

	/**
	 * 配置创建一个 Servlet 过滤器，称为 springSecurityFilterChain 负责应用程序内的所有安全性
	 * （保护应用程序 URL，验证提交的用户名和密码，重定向到登录表单等）
	 * @return
	 */
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
             User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);

    /*
        //为单个用户配置内存中身份验证
        InMemoryUserDetailsManager manager1 = new InMemoryUserDetailsManager();
        manager1.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
        return manager1;
        */


        /*
        //为多个个用户配置内存中身份验证
        //确保密码编码正确
        User.UserBuilder users = User.withDefaultPasswordEncoder();
        InMemoryUserDetailsManager manager2 = new InMemoryUserDetailsManager();
        manager2.createUser(users.username("user").password("password").roles("USER").build());
        manager2.createUser(users.username("admin").password("password").roles("USER","ADMIN").build());
        return manager2;
    */
    }


     /**
     * 基于LDAP的身份验证的更新
     * @param auth
     * @throws Exception
     */
    /*@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .ldapAuthentication()  //配置登录表单中的用户名插入的内容{0}
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()   //配置编码器和密码属性的名称
                .passwordEncoder(new LdapShaPasswordEncoder())
                .passwordAttribute("userPassword");
    }*/


    /**
     * 支持基于JDBC的身份验证的更新
     * @param auth
     * @throws Exception
     */
    /*
    @Autowired
    private DataSource dataSource;
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        User.UserBuilder users = User.withDefaultPasswordEncoder();
        auth
                .jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(users.username("user").password("password").roles("USER"))
                .withUser(users.username("admin").password("password").roles("USER","ADMIN"));
    }*/

    /*
    //MapReactiveUserDetailsS​​ervice为自定义service
    @Bean
    public MapReactiveUserDetailsS​​ervice userDetailsS​​ervice(){
        //最小的WebFlux安全配置
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();
        return new MapReactiveUserDetailsService(user);


        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
        UserDetails rob = userBuilder.username("rob")
                .password("rob")
                .roles("USER")
                .build();
        UserDetails admin = userBuilder.username("admin")
                .password("admin")
                .roles("USER","ADMIN")
                .build();
        return new MapReactiveUserDetailsService(rob, admin);
    }*/
}
```