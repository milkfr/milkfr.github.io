---
title: Java Web研习一：Servlet详解
description: Java Web研习一：Servlet详解
categories:
 - Java Web
tags:
 - Java Web
---

### 0x00 Servlet规范和Servlet容器
浏览器发给服务端的是一个HTTP格式的请求，HTTP服务器收到这个请求后，需要调用服务端程序来处理，服务端程序就是写的Java类

一般来说不同的请求由不同的Java类处理，服务器根据HTTP协议的类别和参数不同调用不同的Java类最直接的方法就是用if-else逻辑判断，这样HTTP服务器的代码就和业务代码逻辑耦合在一起，新增业务方法需要改进HTTP服务器代码

解决这个耦合的办法就是统一规定出一些接口，业务类实现这个接口，这就是一帮古人和大佬定义的Servlet接口，也常把实现Servlet接口的业务类叫做Servlet，此时HTTP服务从选择使用的Java类变成了选择使用的Servlet，服务器还是需要做判断，此时那帮人又发明了Servlet容器，HTTP服务器把请求直接交给Servlet容器，而Servlet容器会将请求转发到具体的Servlet，因此，Servlet接口其实是Servlet容器根具体业务之间的接口

如下图比较清晰

![0-1](https://milkfr.github.io/assets/images/posts/2019-01-01-javaweb-servlet/0-1.png)

HTTP服务器不直接调用业务类，而把请求交给容器来处理，容器通过Servlet接口调用业务类，因此，Servlet接口和Servlet容器达到了HTTP服务器与业务类解耦的目的

Servlet接口和Servlet容器这一整套规范叫做Servlet规范，Tomcat、Jetty都按照Servlet规范实现了Servlet容器，同时它们具有HTTP服务器的功能，Java程序员要实现新功能，就是实现一个Servlet，并把它注册到Tomcat（Servlet容器）中，剩下的事情由Tomcat处理

其实本身Servlet是不在乎通信协议是什么的，规范提供的GenericServlet抽象类，可以通过它实现Servlet，但是大多数Servlet是在HTTP环境中处理的，因此Servelt规范提供了HttpServlet继承GenericServlet，并加入HTTP特性，通过继承HttpServlet来实现Servlet，只需要重写doGet和doPost两个方法，下面通过示例简单演示一下

### 0x01 编写和运行一个HttpServlet
我们通过编写和运行一个HttpServlet，大致了解以下Servlet和Tomcat的配合，步骤如下
1. 下载并安装JDK、Tomcat
2. 编写一个继承HttpServlet的Java类
3. 将Java类文件编译成Class文件
4. 建立Web应用的目录结构，配置web.xml
5. 启动Tomcat并验证

#### 下载并安装JDK、Tomcat
官网下载安装，配置环境变量，这一步跳过

注意需要用到Tomcat目录下的lib目录下的`servlet-api.jar`，使用IDE编辑时提示报错需要加上这个类为lib

#### 编写一个继承HttpServlet的Java类
```
import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;


public class MyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        System.out.println("MyServlet doGet");
        PrintWriter out = resp.getWriter();
        resp.setContentType("text/html;charset=utf-8");
        out.println("<strong>My Servlet!</strong><br>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        System.out.println("MyServlet doPost");
        PrintWriter out = resp.getWriter();
        resp.setContentType("text/html;charset=utf-8");
        out.println("<strong>My Servlet!</strong><br>");
    }
}
```

#### 将Java类文件编译成Class文件
`$ javac -cp ./servlet-api.jar MyServlet.java`

#### 建立Web应用的目录结构，配置Web.xml
在Tomcat的webapps目录下，建立以下结构
```
- webapps
  - MyWebApp
    - WEB-INF
      - classes
        - MyServlet.class
      - web.xml
```

web.xml内容如下，注意servlet和servlet-mapping两个标签里servlet-name要保持一致
```
<?xml version="1.0" encoding="UTF-8"?> 
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
  http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">
  <description> Servlet Example. </description>
  <display-name> MyServlet Example </display-name>
  <request-character-encoding>UTF-8</request-character-encoding>


  <servlet>
    <servlet-name>myServlet</servlet-name>
    <servlet-class>MyServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>myServlet</servlet-name>
    <url-pattern>/myservlet</url-pattern>
  </servlet-mapping>
</web-app>
```

#### 启动Tomcat并验证
在Tomcat目录下执行startup.sh，浏览器访问`http://localhost:8080/MyWebApp/myservlet`

Tomcat目录下的logs文件夹catalina.out文件里可以找到System.out的信息`doGet`

### 0x02 Servlet接口
用IDE编写一个文件implement Servlet，查看Servlet接口定义的5个方法
```
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class MyServlet implements Servlet {
    
    @Override
    public void init(ServletConfig servletConfig) throws ServletException {}

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {}

    @Override
    public String getServletInfo() {
        return null;
    }

    @Override
    public void destroy() {}
    
}
```

对上面的这些接口，我们要探究的地方在于：
1. 5个方法各自的作用
2. Servlet的生命周期
3. ServletConfig和ServletContext
4. ServletRequest和ServletResponse

#### 5个方法各自的作用
顾名思义：init和destroy是在Servlet初始化是销毁时调用的，用来配置资源和销毁资源，比如打开和关闭数据库

service方法是Servlet的核心，每一个用户请求对应一个Servlet的service方法，在HttpServlet中就是调用doGet和doPost方法，这个方法的两个参数ServletRequest和ServletResponse用来封装请求和响应信息，所以本质上这两个类是对通信协议的封装

getServletConfig方法获取servletConfig这个类，这个类的作用是封装Servlet的初始化参数和ServletContext对象，分别提供web.xml配置的参数和servlet的环境配置

getServletInfo方式是一个可选的方法，返回servlet有关信息，比如作者、版本、版权等

#### Servlet的生命周期
1. 加载Servlet：当Tomcat第一次访问Servlet的时候，Tomcat会负责创建Servlet的实例
2. 初始化：当Servlet被实例化后，Tomcat会调用init()方法初始化这个对象
3. 处理服务：当浏览器访问Servlet的时候，Servlet 会调用service()方法处理请求
4. 销毁：当Tomcat关闭时或者检测到Servlet要从Tomcat删除的时候会自动调用destroy()方法，让该实例释放掉所占的资源。一个Servlet如果长时间不被使用的话，也会被Tomcat自动销毁
5. 卸载：当Servlet调用完destroy()方法后，等待垃圾回收。如果有需要再次使用这个Servlet，会重新调用init()方法进行初始化操作。
6. 简单总结：只要访问Servlet，service()就会被调用，init()只有第一次访问Servlet的时候才会被调用，destroy()只有在Tomcat关闭的时候才会被调用。

#### ServletConfig和ServletContext
ServletConfig对象可以读取web.xml中配置的初始化参数，这样可以让程序更加灵活

比如web.xml中配置如下内容，就可以在程序中通过`this.getServletConfig().getInitParameter("name");`获取name的value

```
<servlet>
  <servlet-name>Demo1</servlet-name>
  <servlet-class>Demo1</servlet-class>
  <init-param>
    <param-name>name</param-name>
    <param-value>value</param-value>
  </init-param>
</servlet>
<servlet-mapping>
  <servlet-name>Demo1</servlet-name>
  <url-pattern>/Demo1</url-pattern>
</servlet-mapping>
```

还可以通过ServletConfig对象获取ServletContext对象，当Tomcat启动的时候，就会创建一个ServletContext对象，代表当前站点，这个对象的作用如下
1. 所有Servlet共享一个ServletContext对象，所以Servlet之间可以通过ServletContext实现通讯
2. ServletConfig是获取web.xml中单个Servlet的参数信息，ServletContext可以获取整个Web站点的参数信息
3. 可以利用ServletContext读取站点的资源文件
4. 实现Servlet的转发（主要用ServletRequest转发，用ServletContext转发不多）

#### ServletRequest和ServletResponse
ServletRequest用来封装请求信息，ServletResponse用来封装响应信息，因此本质上这两个类是对通信协议的封装

可以通过HttpServletRequest来获取所有请求相关的信息，包括请求路径、Cookie、HTTP头、请求参数，创建和获取Session，而HttpServletResponse是用来封装HTTP响应的

所以对HTTP协议的理解就是对两个类的理解

### 0x03 Servlet容器
在这里我们要了解，Servlet容器如何与Servlet接口结合，所以我们要了解
1. Servlet容器的工作流程
2. Servlet注册到Servlet容器的方式
3. 如何定制和扩展Servlet容器功能

#### Servlet的工作流程
如下图所示

![3-1](https://milkfr.github.io/assets/images/posts/2019-01-01-javaweb-servlet/3-1.png)

Tomcat包含HTTP服务器和Servlet容器的功能

1. 当用户请求某个资源时，HTTP服务器会用一个ServletRequest对象把客户的请求信息封装起来，然后调用Servelet容器的service方法
2. Servelt容器拿到请求后，根据请求的URL和Servlet的映射关系，找到对应的Servlet
3. 如果Servlet没有被加载，就用反射机制创建这个Servlet，并调用Servlet的init方法完成初始化
4. 调用Servlet的service方法来处理请求
5. 把ServletResponse对象返回给HTTP服务器，HTTP服务器会把响应发送给客户端

#### Servlet注册到Servlet容器的方式
```
- WebAPP
    - WEB-INF  
        - lib  # 应用所需的jar包
        - web.xml  # 配置文件，用来配置Servlet等 
        - classes  # 应用类，如Servlet类
    - META-INF  # 目录存放工程的一些信息
```

Web应用程序有一定的目录结构，在这个目录下分别放置了Servlet类文件、配置文件及静态资源，Servlet容器通过读取配置文件，就能找到并加载Servlet

Servlet规范里定义了ServletContext这个接口来对应一个Web应用，也就是我们上文提到的ServletContext，通过ServletConfig可以获取

#### 如何定制和扩展Servlet容器功能
当Servlet规范不能满足业务个性化的定制需求时，就需要设计一个规范或者一个中间件来充分考虑到扩展性，Servlet规范提供了两种机制：Filter和Listener

Filter是过滤器，允许对请求和响应做统一的定制处理，实现方式和Servlet一样，实现Filter接口，

```
public class FilterDemo1 implements Filter {
    public void destroy() {}

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        chain.doFilter(req, resp);
    }

    public void init(FilterConfig config) throws ServletException {}
}
```

web.xml中配置

```
<filter>
    <filter-name>FilterDemo1</filter-name>
    <filter-class>FilterDemo1</filter-class>
</filter>
<filter-mapping>
    <filter-name>FilterDemo1</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

Web应用部署完成后，Servlet容器需要实例化Filter并把Filter链接成一个FilterChain，当请求进来时，获取第一个Filter并调用doFilter方法，doFilter方法负责调用这个FilterChain中的下一个Filter

工作流程大概：`HTTP Request->ServletRequest->Filter(doFilter)->...->Filter(doFilter)->Service->ServletResponse->Filter(doFilter)->...->Filter(doFilter)->HTTP Response`

Listener是监听器，常用来统计在线人数，访问量等，当Web应用在Servlet容器中运行时，Servlet容器内部会不断的发生各种事件，如Web应用的启动和停止、用户请求到达等，Servlet容器提供了一些默认的监听器来监听这些事件，当事件发生时，Servlet容器会负责调用监听器的方法，当然，可以定义自己的监听器去监听感兴趣的事件，将监听器配置在web.xml中

在Servlet规范中定义了多种类型的监听器，它们用于监听的事件源分别ServletContext，HttpSession和ServletRequest这三个域对象，和其他事件监听器略有不同的是，servlet监听器的注册不是直接注册在事件源上，而是由Web容器负责注册，开发人员只需要在web.xml中配置`<listener>`标签

实现接口类似如下：

```
public class Listener1 implements ServletContextListener,
    HttpSessionListener, ServletRequestListener {

    // Public constructor is required by servlet spec
    public Listener1() {
    }

    public void contextInitialized(ServletContextEvent sce) {
    }

    public void contextDestroyed(ServletContextEvent sce) {
    }


    public void sessionCreated(HttpSessionEvent se) {
    }

    public void sessionDestroyed(HttpSessionEvent se) {
    }

    @Override
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {

    }
}
```

Filter和Listener的本质区别：

Filter是干预过程的：它是过程的一部分，是基于过程行为的

Listener是基于状态的，任何行为改变统一个状态，触发的事件是一致的


