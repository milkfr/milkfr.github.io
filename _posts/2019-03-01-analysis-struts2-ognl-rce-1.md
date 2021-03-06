---
title: struts2基于OGNL的RCE漏洞分析1——从s2-001看如何定位返回包数据流转造成的RCE
description: 这篇文章原来是我的s2-001漏洞分析文章，如今翻新一下，写一个短系列，讲讲对Struts2的基于OGNL的RCE漏洞的分析，这一篇写写不通过代码diff怎么定位漏洞所在
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

这里假设知道PoC和存在漏洞的版本，不知道漏洞出现在哪里，如何定位出漏洞所在位置，以s2-001为例

### 0x00 漏洞信息
#### 漏洞公告
[漏洞公告](https://cwiki.apache.org/confluence/display/WW/S2-001)

#### 环境搭建
[参考之前的文章](https://milkfr.github.io/%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/2019/01/20/env-struts2/)

将pom.xml中的struts2版本改成2.0.5，maven仓库中2.0.1的版本都找不到，只能找到稍高一点的在漏洞影响范围的小版本

编写web.xml

```
<!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtd/web-app_2_3.dtd" >

<web-app>
  <display-name>Archetype Created Web Application</display-name>
  <filter>
    <filter-name>struts2</filter-name>
    <filter-class>org.apache.struts2.dispatcher.FilterDispatcher</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>struts2</filter-name>
    <url-pattern>*</url-pattern>
  </filter-mapping>
</web-app
```

编写Action

```
package io.github.milkfr.struts2demo;
import com.opensymphony.xwork2.ActionSupport;


public class LoginAction extends ActionSupport {
    private String username = null;
    private String password = null;

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String execute() throws Exception {
        if ((this.username.isEmpty()) || (this.password.isEmpty())) {
            return "error";
        }
        if ((this.username.equalsIgnoreCase("admin"))
                && (this.password.equals("admin"))) {
            return "success";
        }
        return "error";
    }

    public String hello() {
        if ((this.username.isEmpty()) || (this.password.isEmpty())) {
            return "error";
        }
        if ((this.username.equalsIgnoreCase("admin"))
                && (this.password.equals("admin"))) {
            return "success";
        }
        return "error";
    }
}
```

编写index.jsp

```
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>用户登录</title>
</head>
<body>
<h1>用户登录</h1>
<s:form action="login">
    <s:textfield name="username" label="username" />
    <s:textfield name="password" label="password" />
    <s:submit></s:submit>
</s:form>

</body>
</html>
```

编写welcome.jsp

```
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>S2-001</title>
</head>
<body>
<p>Hello <s:property value="username"></s:property></p>
</body>
</html>
```

编写struts.xml

```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE struts PUBLIC
        "-//Apache Software Foundation//DTD Struts Configuration 2.3//EN"
        "http://struts.apache.org/dtds/struts-2.3.dtd">

<struts>
    <package name="privilige" extends="struts-default">
        <action name="login" class="io.github.milkfr.struts2demo.LoginAction">
            <result name="success">/welcome.jsp</result>
            <result name="error">/index.jsp</result>
        </action>
    </package>
</struts>
```

配置好tomcat用IDEA开始debug

![0-1](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/0-1.png)

#### 漏洞利用
用户名框输入`%{1+1}`会被解析成2返回

![0-2](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/0-2.png)

![0-3](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/0-3.png)

这里就有了命令执行的问题

### 0x01 漏洞分析
#### 如何开始定位
其实网上很多从`org.apache/struts2/views/jsp/ComponentTagSupport.class`开始分析的，不必对修复版本的代码diff的话，我觉得是很难定位到这里的，我分析的时候，能找到这个类就花了很长时间，我之前还整体分析过struts2的整个构架，还是不容易找到这个入口，不知道很多年前人们是怎么定位的，可能牛人还是多吧

网上很多分析定位处理这个类，但是没有说怎么定位的，我推测是根据代码的diff来看的，我是这样分析的

一般来讲，这个命令执行，可能出现的地方是OGNL表达式在处理数据流转的时候，也就是数据从HTTP请求包体转换成Struts2的Request对象（不一定代码写的就是Request，只是比喻）和Response转换成返回的HTTP包体的时候，因为Struts2对Servlet进行封装以隔离web容器和应用代码的设计，用OGNL表达式处理据流转，也就是将弱类型的HTTP包体和强类型的Java语言进行数据转换的时候

也就是当我们能在action当execute中获取到username、password的值的时候就完成了HTTP请求包到Java世界的数据转换，action的return之后，就开始了Java世界到HTTP返回包到数据转换

所以我们首先要判断是请求还是返回时发生到命令执行

#### 排除HTTP包转到Java的数据流转造成的漏洞
很简单，断点打在action的execute的函数体中

![1-1](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/1-1.png)

可以看到此时，我们username和password都没有问题，作为字符类型保存了传入的值

然后我们一步步step over和step in

可以得到的调用栈关系如下

![1-2](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/1-2.png)

DefaultActionInvocation里执行了action的execute

最后来到ServletDispatcherResult的doExecute方法，如下

```
public void doExecute(String finalLocation, ActionInvocation invocation) throws Exception {
    if (log.isDebugEnabled()) {
        log.debug("Forwarding to location " + finalLocation);
    }

    PageContext pageContext = ServletActionContext.getPageContext();
    if (pageContext != null) {
        pageContext.include(finalLocation);
    } else {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        RequestDispatcher dispatcher = request.getRequestDispatcher(finalLocation);
        if (dispatcher == null) {
            response.sendError(404, "result '" + finalLocation + "' not found");
            return;
        }

        if (!response.isCommitted() && request.getAttribute("javax.servlet.include.servlet_path") == null) {
            request.setAttribute("struts.view_uri", finalLocation);
            request.setAttribute("struts.request_uri", request.getRequestURI());
            dispatcher.forward(request, response);
        } else {
            dispatcher.include(request, response);
        }
    }
}
```

执行到`dispatcher.forward`时候，就无法继续debug了，因为IDE显示的是Tomcat的一些方法，这时候IDE不能帮我们定位代码了

#### 定位Java到HTTP Response数据流转的代码
我也是在这里有难度，不知道网上的人是怎么定位出之后的代码的，感觉大家都说得比较含糊，或者根本不说

这里有了网上之后定位的方向的提示，也很容易理解，forward其实就是当前的Servlet转到下一个Servlet里，下一个Servlet其实就是error的JSP页面，也就是index_jsp.class这个编译好的文件，因为任意的jsp也是一个Servlet，这一点很容易想通，不明白可以网上查一下jsp本质之类的，我看过很多文章这么介绍jsp

我们可以在tomcat的项目部署路径下找到它

```
// 省略一些导入
import org.apache.struts2.views.jsp.PropertyTag;
// 省略一些导入

public final class index_jsp extends HttpJspBase implements JspSourceDependent, JspSourceImports {
    // 略过一些属性和方法
}

```

可以看到，和struts2有关的只有这一个类，它继承了ComponentTagSupport这个类，也就是很多分析文章的起点，这个类有继承自`javax.servlet.jsp.tagext.BodyTagSupport`这个jsp的类

```
public class PropertyTag extends ComponentTagSupport {}
```

之后我们可以按网上分析文章一样，从ComponentTagSupport这里开始打断点debug，因为一开始我觉得非开发的我是不知道doStartTag和doEndTag是开闭jsp标签的，所以我找到这个很困难，可能有些朋友对jsp熟悉，所以能找到继承的BodyTagSupport类才找到它吧

#### 解析过程分析
```
public abstract class ComponentTagSupport extends StrutsBodyTagSupport {
    public int doEndTag() throws JspException {
        this.component.end(this.pageContext.getOut(), this.getBody());
        this.component = null;
        return 6;
    }

    public int doStartTag() throws JspException {
        this.component = this.getBean(this.getStack(), (HttpServletRequest)this.pageContext.getRequest(), (HttpServletResponse)this.pageContext.getResponse());
        Container container = Dispatcher.getInstance().getContainer();
        container.inject(this.component);
        this.populateParams();
        boolean evalBody = this.component.start(this.pageContext.getOut());
        if (evalBody) {
            return this.component.usesBody() ? 2 : 1;
        } else {
            return 0;
        }
    }
}
```

doStartTag处理jsp的标签开口，这里是注册一个component到struts的容器中，这个容器概念在我博客里讲Struts2框架的整体构成说过，这里不必太在意，不是很重要

doEngTag是闭合jsp的标签处理，跟踪进UIBean.end->UIBean.evaluateParams

![1-3](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/1-3.png)

对evaluateParams进行debug可以看到，username外面被套`%{}`，执行完addParameter函数后nameValue的值就是2了

然后debug进findValue，然后进入TextParseUtil.translateVariables中，可以看到我们的最终目标translateVariables

```
public static Object translateVariables(char open, String expression, ValueStack stack, Class asType, TextParseUtil.ParsedValueEvaluator evaluator) {
    Object result = expression;

    while(true) {
        int start = expression.indexOf(open + "{");
        int length = expression.length();
        int x = start + 2;
        int count = 1;

        while(start != -1 && x < length && count != 0) {
            char c = expression.charAt(x++);
            if (c == '{') {
                ++count;
            } else if (c == '}') {
                --count;
            }
        }

        int end = x - 1;
        if (start == -1 || end == -1 || count != 0) {
            return XWorkConverter.getInstance().convertValue(stack.getContext(), result, asType);
        }

        String var = expression.substring(start + 2, end);
        Object o = stack.findValue(var, asType);
        if (evaluator != null) {
            o = evaluator.evaluate(o);
        }

        String left = expression.substring(0, start);
        String right = expression.substring(end + 1);
        if (o != null) {
            if (TextUtils.stringSet(left)) {
                result = left + o;
            } else {
                result = o;
            }

            if (TextUtils.stringSet(right)) {
                result = result + right;
            }

            expression = left + o + right;
        } else {
            result = left + right;
            expression = left + right;
        }
    }
}
```

看断点截图

![1-4](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/1-4.png)

![1-5](https://milkfr.github.io/assets/images/posts/2019-03-01-analysis-struts2-ognl-rce-1/1-5.png)

第一次从`%{username}`中用`%{}`包裹，用OGNL也就是stack.findValue获取了username的值，也就是`%{1+1}`

第二次因为`%{1+1}`也满足用`%{}`包裹的条件，获取1+1的OGNL的值，也就是2，造成了代码执行

分析上面的代码，当`%{}`的结构嵌套时，会在while中会递归调用，通过对start、end、count、x和c的值进行计算的过程中计算递归的要求

#### 漏洞修复
没有去找对应版本看怎么修复的，因为麻烦，看别人的分析文章，是增加了一个loopCount和maxLoopCount对递归次数做了限制

用户上传的参数值，在我们上面的分析中，struts2都会先给它加一个`%{}`，按理，struts2自己加了几次这个，maxLoopCount应该即使多少次，除了框架自己加的，其他的不处理，这样的修复方式应该说感觉是比正则过滤修复更加合理的方式

### 0x02 反思如何定位漏洞所在
回顾我们上面的过程

* 搭建环境
* 根据数据流转导致漏洞的规则，从action开始debug，定位是HTTP请求包转换成Struts2的Request的过程存在问题还是Struts2的Response转换成HTTP返回包存在问题
* 定位出Response过程出现问题后，IDE的debug过程存在问题，不能跟进forward，因为进入的jsp的servlet
* 发现出struts2中处理jsp的部分继续debug，可以定位到漏洞发生的时刻
* debug过程一般step over，值发生变化后step in，进一步定位

这里有几点

* 数据流程的过程其实是几乎所有web框架通用的，可以在其他分析中复用
* forward之后的jsp对应代码寻找和对java web的知识储备有关，是瓶颈所在，只能通过本身开发和对框架了解或者通过几次这样的分析才能明白
* Response转换成HTTP返回过程中存在的问题不止于jsp的处理，对struts2框架了解的话，struts2封装了各种类型的Return，处理HTTP返回的各种情况，jsp的标签处理只是一种，这样因jsp出现的漏洞也会出现在其他类似的处理中，对这些有了解更好