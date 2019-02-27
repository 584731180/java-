spring-security

**1.概念**

**定义**:Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。一般来说，Web 应用的安全性包括用户认证（Authentication）和用户授权（Authorization）两个部分。用户认证指的是验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。用户认证一般要求用户提供用户名和密码。系统通过校验用户名和密码来完成认证过程。用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限 。

所以在理解这个框架之前,我们最少得清楚三个表.用户表,角色表,权限表,用户表和权限表之间并没有直接关系.用户表和角色表之间是多对多,角色表和权限表之间是多对多.看一个用户有什么访问权限,首先看这个用户属于什么角色,这个角色对应什么权限.因为此次开发中,我们的权限都是在配置文件中固定的,所以就没有牵扯到权限表.

**权限授予给角色,角色授予给用户**

**2.实现步骤**

2.1,配置web.xml

​     <!--初始化Spring容器-->
<context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>classpath:spring-security.xml</param-value>
</context-param>
<listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
</listener>

<!--加载Spring-security权限过滤器-->
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>

**2.配置spring-security.xml**

!-- 设置页面不登陆也可以访问 -->
    <http pattern="/*.html" security="none"></http>

​    <http pattern="/css/**" security="none"></http>
    <http pattern="/img/**" security="none"></http>
    <http pattern="/js/**" security="none"></http>
    <http pattern="/plugins/**" security="none"></http>
    **<http pattern="/seller/add.do" security="none"></http>**
    <!-- 页面的拦截规则    use-expressions:是否启动SPEL表达式 默认是true -->

​     如果不配置    access="hasRole('ROLE_USER')" />

​    <http use-expressions="false">
        <!-- 当前用户必须有ROLE_USER的角色 才可以访问根目录及所属子目录的资源 -->

/* 表示的是该目录下的资源，只包括本级目录不包括下级目录
/** 表示的是该目录以及该目录下所有级别子目录的资源

​        <intercept-url pattern="/**" access="ROLE_SELLER"/>
        <!-- 开启表单登陆功能 -->
        <form-login  login-page="/shoplogin.html" default-target-url="/admin/index.html"  authentication-failure-url="/shoplogin.html" always-use-default-target="true"/>
        <csrf disabled="true"/>
        <headers>
            <frame-options policy="SAMEORIGIN"/>
        </headers>
        <logout/>
    </http>


​    <!-- 认证管理器 -->
    <authentication-manager>
        <authentication-provider user-service-ref="userDetailService">
            <password-encoder ref="bcryptEncoder"></password-encoder>
        </authentication-provider>
    </authentication-manager>
    <!-- 认证类 -->
    <beans:bean id="userDetailService" class="com.pinyougou.service.UserDetailsServiceImpl">
        <beans:property name="sellerService" ref="sellerService"></beans:property>
    </beans:bean>
    <!-- 引用dubbo 服务 -->
    <dubbo:application name="pinyougou-shop-web" />
    <dubbo:registry address="zookeeper://192.168.25.131:2181"/>
    <!--自定义认证类-->
    <dubbo:reference
            id="sellerService"
            interface="com.pinyougou.sellergoods.service.SellerService"/>
   <!--密码加密-->
    <beans:bean
            id="bcryptEncoder"
            class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
</beans:beans>



//如果说不行数据库查,比如运营商登录系统,可配置

<!-- 认证管理器 -->
<authentication-manager>
	<authentication-provider>
		<user-service>
			<user name="admin" password="123456" authorities="ROLE_ADMIN"/>
			<user name="sunwukong" password="dasheng" authorities="ROLE_ADMIN"/>
		</user-service>
	</authentication-provider>	
</authentication-manager>

`CSRF（Cross-site request forgery）跨站请求伪造，也被称为“One Click Attack”或者 Session` 
`Riding，通常缩写为 CSRF 或者 XSRF，是一种对网站的恶意利用。`

3.实现serDetailService  重写loadUserByUsername方法

```
public class UserDetailsServiceImpl implements UserDetailsService {
    //通过set方法引入sellerService
    private SellerService sellerService;

    public void setSellerService(SellerService sellerService) {
        this.sellerService = sellerService;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //通过前台的传来的username查询seller对象
        TbSeller seller = sellerService.findOne(username);
        //创建一个角色集合
        ArrayList<GrantedAuthority> list = new ArrayList<>();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_SELLER");
        list.add(authority);
        //判断商家是否为空
        if (seller!=null){
        //判断商家的状态是否为1,就是已经注册
            if (seller.getStatus().equals("1")){
                return new User(username, seller.getPassword(), list);
                     
    //第一个参数：认证用户名
    //第二个参数:认证密码
    //第三个参数 :账户是否可用
    //第四 --第六  ：操作账户信息 ture
    //第七个参数:角色集合
            }else {
                return  null;
            }
        }else {
            return null;
        }

    }
}
```

2.用户名回显.

1.页面  < ng-ng-init="getUsername()" >

2.  js

   ```
   app.controller("loginController",function ($scope,loginService) {
       $scope.getUsername=function () {
           loginService.getUsername().success(
               function (responce) {
               $scope.loginName=responce.loginName
           })
       }
   
   })
   
   ```

3web  controller

​           

```
@RestController
@RequestMapping("/login")
public class LoginController {

    @RequestMapping("/name")
    public Map getUserName(){
 String name = SecurityContextHolder.getContext().getAuthentication().getName();
        Map<String, String> map = new HashMap<>();
        map.put("loginName", name);
        return  map;

    }
}

```

**商家申请入驻的密码要使用 BCrypt 算法进行加密存储，修改 SellerController.java 的 add 方法**

//密码加密

分为两种:1.可逆

​                 2.不可逆

我们学过两种, MD5 和BCrypt  都属于不可逆

MD5,32位,相同密码加密生产的字符串是相等的

BCrypt:60位,相同的密码得到的字符串是不相等,是因为它每次在加密的时候回随机加盐,每次的盐是不同的.校验它会自动的把盐提出来,再进行校验.

```
@RequestMapping("/add")
public Result add(@RequestBody TbSeller seller){
	//密码加密
	BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
	String password = passwordEncoder.encode(seller.getPassword());//加密
	seller.setPassword(password);
	
	try {
		sellerService.add(seller);
		return new Result(true, "增加成功");
	} catch (Exception e) {
		e.printStackTrace();
		return new Result(false, "增加失败");
	}
}
```

