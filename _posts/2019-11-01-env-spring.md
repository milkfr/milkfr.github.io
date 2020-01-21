---
title: Spring环境搭建
description: 记录搭建Spring的环境，根据《精通Spring 4.x 企业应用开发实战》搭一个有一点点复杂的Demo
categories:
 - 环境搭建
tags:
 - 环境搭建
---

### 0x00 IDEA新建项目
直接新建一个maven项目就可以

新建项目后，创建项目目录如下

```
.
├── src
   ├── main
      ├── java
      │   └── io
      │       └── github
      │           └── milkfr
      │               ├── dao
      │               │   ├── LoginLogDao.java
      │               │   └── UserDao.java
      │               ├── domain
      │               │   ├── LoginLog.java
      │               │   └── User.java
      │               ├── service
      │               │   └── UserService.java
      │               └── web
      │                   ├── LoginCommand.java
      │                   └── LoginController.java
      ├── resources
      │   └── smart-context.xml
      └── webapp
          ├── WEB-INF
          │   ├── jsp
          │   │   ├── login.jsp
          │   │   └── main.jsp
          │   ├── smart-servlet.xml
          │   └── web.xml
          ├── index.jsp
          └── log4j.properties
```

### 0x01 maven配置依赖
pom.xml文件内容如下

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>io.github.milkfr</groupId>
    <artifactId>sample</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <!-- spring 依赖-->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-beans</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context-support</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-jdbc</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>${spring.version}</version>
        </dependency>

        <dependency>
            <groupId>commons-dbcp</groupId>
            <artifactId>commons-dbcp</artifactId>
            <version>${commons-dbcp.version}</version>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>${mysql.version}</version>
        </dependency>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>servlet-api</artifactId>
            <version>${servlet.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.aspectj</groupId>
            <artifactId>aspectjweaver</artifactId>
            <version>${aspectj.version}</version>
        </dependency>


        <dependency>
            <groupId>org.testng</groupId>
            <artifactId>testng</artifactId>
            <version>${testng.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-test</artifactId>
            <version>${spring.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <!-- jetty插件 -->
            <plugin>
                <groupId>org.mortbay.jetty</groupId>
                <artifactId>maven-jetty-plugin</artifactId>
                <version>6.1.25</version>
                <configuration>
                    <connectors>
                        <connector implementation="org.mortbay.jetty.nio.SelectChannelConnector">
                            <port>8000</port>
                            <maxIdleTime>60000</maxIdleTime>
                        </connector>
                    </connectors>
                    <contextPath>/bbs</contextPath>
                    <scanIntervalSeconds>0</scanIntervalSeconds>
                </configuration>
            </plugin>

        </plugins>
    </build>

    <properties>
        <file.encoding>UTF-8</file.encoding>
        <spring.version>4.2.2.RELEASE</spring.version>
        <mysql.version>8.0.15</mysql.version>
        <servlet.version>3.0-alpha-1</servlet.version>
        <aspectj.version>1.8.1</aspectj.version>
        <commons-codec.version>1.9</commons-codec.version>
        <commons-dbcp.version>1.4</commons-dbcp.version>
        <hibernate.validator.version>5.0.2.Final</hibernate.validator.version>
        <jetty.version>8.1.8.v20121106</jetty.version>
        <slf4j.version>1.7.5</slf4j.version>
        <testng.version>6.8.7</testng.version>
    </properties>
</project>
```

照着配，能增加和删除就可以

注意这里jetty相关的配置，以前我只会用IDE中配置Web应用服务器

这里学到了maven中配置服务器插件，配置好后，在IDEA工程的Maven Projects管理窗口运行`jetty:run`

### 0x02 数据库准备工作
```
# 建立数据库
DROP DATABASE IF EXISTS sampledb;
CREATE DATABASE sampledb DEFAULT CHARACTER SET utf8;
USE sampledb;

##创建用户表
CREATE TABLE t_user (
   user_id   INT AUTO_INCREMENT PRIMARY KEY,
   user_name VARCHAR(30),
   password  VARCHAR(32),
   credits INT,
   last_visit datetime,
   last_ip  VARCHAR(23)
)ENGINE=InnoDB; 

##创建用户登录日志表
CREATE TABLE t_login_log (
   login_log_id  INT AUTO_INCREMENT PRIMARY KEY,
   user_id   INT,
   ip  VARCHAR(23),
   login_datetime datetime
)ENGINE=InnoDB; 

##插入初始化数据
INSERT INTO t_user (user_name,password) 
             VALUES('admin','123456');
COMMIT;
```

### 0x03 代码
#### 建立领域对象
```
// domain/User.java
package io.github.milkfr.domain;

import java.io.Serializable;
import java.util.Date;

public class User implements Serializable {
    private int userId;
    private String userName;
    private String password;
    private int credits;
    private String lastIp;
    private Date lastVisit;
    public String getLastIp() {
        return lastIp;
    }
    public void setLastIp(String lastIp) {
        this.lastIp = lastIp;
    }
    public Date getLastVisit() {
        return lastVisit;
    }
    public void setLastVisit(Date lastVisit) {
        this.lastVisit = lastVisit;
    }
    public int getUserId() {
        return userId;
    }
    public void setUserId(int userId) {
        this.userId = userId;
    }
    public String getUserName() {
        return userName;
    }
    public void setUserName(String userName) {
        this.userName = userName;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public int getCredits() {
        return credits;
    }
    public void setCredits(int credits) {
        this.credits = credits;
    }
}

// domain/LoginLog.java
package io.github.milkfr.domain;

import java.io.Serializable;
import java.util.Date;

public class LoginLog implements Serializable {
    private int loginLogId;
    private int userId;
    private String ip;
    private Date loginDate;
    public String getIp() {
        return ip;
    }
    public void setIp(String ip) {
        this.ip = ip;
    }
    public Date getLoginDate() {
        return loginDate;
    }
    public void setLoginDate(Date loginDate) {
        this.loginDate = loginDate;
    }
    public int getLoginLogId() {
        return loginLogId;
    }
    public void setLoginLogId(int loginLogId) {
        this.loginLogId = loginLogId;
    }
    public int getUserId() {
        return userId;
    }
    public void setUserId(int userId) {
        this.userId = userId;
    }
}
```

#### 建立数据访问层
```
// dao/UserDao.java
package io.github.milkfr.dao;

import io.github.milkfr.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;

@Repository
public class UserDao {
    private JdbcTemplate jdbcTemplate;

    private  final static String MATCH_COUNT_SQL = " SELECT count(*) FROM t_user  " +
            " WHERE user_name =? and password=? ";
    private  final static String UPDATE_LOGIN_INFO_SQL = " UPDATE t_user SET " +
            " last_visit=?,last_ip=?,credits=?  WHERE user_id =?";

    public int getMatchCount(String userName, String password) {

        return jdbcTemplate.queryForObject(MATCH_COUNT_SQL, new Object[]{userName, password}, Integer.class);
    }

    public User findUserByUserName(final String userName) {
        String sqlStr = " SELECT user_id,user_name,credits "
                + " FROM t_user WHERE user_name =? ";
        final User user = new User();
        jdbcTemplate.query(sqlStr, new Object[] { userName },
                new RowCallbackHandler() {
                    public void processRow(ResultSet rs) throws SQLException {
                        user.setUserId(rs.getInt("user_id"));
                        user.setUserName(userName);
                        user.setCredits(rs.getInt("credits"));
                    }
                });
        return user;
    }

    public void updateLoginInfo(User user) {
        jdbcTemplate.update(UPDATE_LOGIN_INFO_SQL, new Object[] { user.getLastVisit(),
                user.getLastIp(),user.getCredits(),user.getUserId()});
    }

    @Autowired
    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
}

// dao/LoginLogDao.java
package io.github.milkfr.dao;

import io.github.milkfr.domain.LoginLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class LoginLogDao {
    private JdbcTemplate jdbcTemplate;

    //保存登陆日志SQL
    private final static String INSERT_LOGIN_LOG_SQL= "INSERT INTO t_login_log(user_id,ip,login_datetime) VALUES(?,?,?)";

    public void insertLoginLog(LoginLog loginLog) {
        Object[] args = { loginLog.getUserId(), loginLog.getIp(),
                loginLog.getLoginDate() };
        jdbcTemplate.update(INSERT_LOGIN_LOG_SQL, args);
    }

    @Autowired
    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
}
```

Spring2.5以后，可以使用注解的方式定义Bean，比起XML配置，注解方式更简单，被广泛接受，成为趋势，除非没有办法，尽量使用注解方式配置

`Repository`定义一个DAO Bean，使用`@Autowired`将Spring容器中的Bean，也就是`JdbcTemplate Bean`注入进来

`Spring JDBC`的模版类`org.spring.framework.core.JdbcTemplate`帮助减少了`获取连接->创建Statement->执行数据操作->获取结果->关闭Statement->关闭结果集->关闭连接`

#### 建立Service层
```
// service/UserService.java
package io.github.milkfr.service;

import io.github.milkfr.dao.LoginLogDao;
import io.github.milkfr.dao.UserDao;
import io.github.milkfr.domain.LoginLog;
import io.github.milkfr.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private UserDao userDao;
    private LoginLogDao loginLogDao;

    public boolean hasMatchUser(String userName, String password) {
        int matchCount =userDao.getMatchCount(userName, password);
        return matchCount > 0;
    }

    public User findUserByUserName(String userName) {
        return userDao.findUserByUserName(userName);
    }

    @Transactional
    public void loginSuccess(User user) {
        user.setCredits( 5 + user.getCredits());
        LoginLog loginLog = new LoginLog();
        loginLog.setUserId(user.getUserId());
        loginLog.setIp(user.getLastIp());
        loginLog.setLoginDate(user.getLastVisit());
        userDao.updateLoginInfo(user);
        loginLogDao.insertLoginLog(loginLog);
    }

    @Autowired
    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }

    @Autowired
    public void setLoginLogDao(LoginLogDao loginLogDao) {
        this.loginLogDao = loginLogDao;
    }
}
```

`@Service`注解将`UserService`标注成一个服务层Bean

`@Autowired`注解将DAO层的Bean注入

`@Transactional`标注事务注解，让被标注的方法运行在事务环境中

#### JSP页面
```
// webapp/WEB-INF/jsp/login.jsp
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>
<head>
    <title>小春论坛登录</title>
</head>
<body>
<c:if test="${!empty error}">
    <font color="red"><c:out value="${error}" /></font>
</c:if>
<form action="<c:url value="loginCheck.html"/>" method="post">
    用户名：
    <input type="text" name="userName">
    <br>
    密 码：
    <input type="password" name="password">
    <br>
    <input type="submit" value="登录" />
    <input type="reset" value="重置" />
</form>
</body>
</html>

// webapp/WEB-INF/jsp/main/jsp
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>
<head>
    <title>小春论坛登录</title>
</head>
<body>
<c:if test="${!empty error}">
    <font color="red"><c:out value="${error}" /></font>
</c:if>
<form action="<c:url value="loginCheck.html"/>" method="post">
    用户名：
    <input type="text" name="userName">
    <br>
    密 码：
    <input type="password" name="password">
    <br>
    <input type="submit" value="登录" />
    <input type="reset" value="重置" />
</form>
</body>
</html>
```

### 0x04 配置
`log4j`的配置`log4j.properties`不管

#### web.xml配置
```
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="2.5"
         xmlns="http://java.sun.com/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
	http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd">
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>classpath:smart-context.xml</param-value>
    </context-param>
    <listener>
        <listener-class>
            org.springframework.web.context.ContextLoaderListener
        </listener-class>
    </listener>

    <servlet>
        <servlet-name>smart</servlet-name>
        <servlet-class>
            org.springframework.web.servlet.DispatcherServlet
        </servlet-class>
        <load-on-startup>3</load-on-startup>
    </servlet>

    <servlet-mapping>
        <servlet-name>smart</servlet-name>
        <url-pattern>*.html</url-pattern>
    </servlet-mapping>
</web-app>
```

`context-param`的配置是Spring配置文件地址

`listner`配置Spring提供的`ContextLoaderListener`监听器，监听Web容器运行，获取配置和启动Spring容器等操作

`servlet`配置的是Spring MVC的信息，对URL映射关系处理

#### smart-servlet.xml
```
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:p="http://www.springframework.org/schema/p"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
       http://www.springframework.org/schema/context
       http://www.springframework.org/schema/context/spring-context-4.0.xsd">
    <!-- 扫描web包，应用Spring的注解 -->
    <context:component-scan base-package="io.github.milkfr.web"/>

    <!-- 配置视图解析器，将ModelAndView及字符串解析为具体的页面 -->
    <bean
            class="org.springframework.web.servlet.view.InternalResourceViewResolver"
            p:viewClass="org.springframework.web.servlet.view.JstlView"
            p:prefix="/WEB-INF/jsp/"
            p:suffix=".jsp" />

</beans>
```

上面Spring MVC配置有一个契约，`<Servlet名>-servlet.xml`，所以上看servlet配置就需要这个`smart-servlet.xml`

配置对应的service包的注解扫描路径和JSP对应位置，根据service上的注解会自动对应上

#### smart-context.xml
```
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context" xmlns:p="http://www.springframework.org/schema/p"
       xmlns:aop="http://www.springframework.org/schema/aop" xmlns:tx="http://www.springframework.org/schema/tx"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop.xsd http://www.springframework.org/schema/tx http://www.springframework.org/schema/tx/spring-tx.xsd">

    <context:component-scan base-package="io.github.milkfr.dao"/>
    <context:component-scan base-package="io.github.milkfr.service"/>

    <bean id="dataSource" class="org.apache.commons.dbcp.BasicDataSource"
          destroy-method="close"
          p:driverClassName="com.mysql.jdbc.Driver"
          p:url="jdbc:mysql://localhost:3306/sampledb"
          p:username="root"
          p:password="mysql666"/>

    <bean id="jdbcTemplate" class="org.springframework.jdbc.core.JdbcTemplate"
          p:dataSource-ref="dataSource"/>

    <bean id="transactionManager"
          class="org.springframework.jdbc.datasource.DataSourceTransactionManager"
          p:dataSource-ref="dataSource"/>

    <aop:config proxy-target-class="true">
        <aop:pointcut id="serviceMethod"
                      expression="(execution(* io.github.milkfr.service..*(..))) and (@annotation(org.springframework.transaction.annotation.Transactional))" />
        <aop:advisor pointcut-ref="serviceMethod" advice-ref="txAdvice"/>
    </aop:config>

    <tx:advice id="txAdvice" transaction-manager="transactionManager">
        <tx:attributes>
            <tx:method name="*" />
        </tx:attributes>
    </tx:advice>
</beans>
```

在代码resources目录中放Spring的Bean配置文件，名称和`web.xml`中的配置对应

`context`指定将注解的类转化成Bean需要扫描的包

`bean`指定数据库等一些其它类

`aop`和`tx`以AOP的方式为service包下的`@Transactional`注解的方法添加了事物增强

### 0x05 运行
在IDEA工程的Maven Projects管理窗口运行`jetty:run`

访问`127.0.0.1:8000/bbs/index.html`就可以访问到

环境搭建成功
