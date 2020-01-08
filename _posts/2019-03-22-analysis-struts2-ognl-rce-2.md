---
title: struts2基于OGNL的RCE漏洞分析2——从s2-007看如何定位请求包数据流转造成的RCE
description: 承接上一篇，通过s2-007的分析讲讲请求包与struts2数据流转造成的RCE的漏洞定位方式
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

这一篇我们来讲讲请求包与Java世界数据流转造成的漏洞如何定位分析，用s2-007为例，其实按顺序，s2-003和s2-005更好，但试了几次自己建环境，没有成功，网上看可能是Tomcat需要低版本的问题，觉得有点麻烦，就跳到了s2-007

### 0x00 漏洞信息
#### 漏洞公告
[官方公告](https://cwiki.apache.org/confluence/display/WW/S2-007)

#### 环境搭建
和上一篇一样，这次版本改成2.2.3

web.xml 

```
<!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtd/web-app_2_3.dtd" >

<web-app>
  <display-name>Archetype Created Web Application</display-name>
  <filter>
    <filter-name>struts2</filter-name>
    <filter-class>org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>struts2</filter-name>
    <url-pattern>*</url-pattern>
  </filter-mapping>
</web-app>
```

编写Action

```
package io.github.milkfr;
import com.opensymphony.xwork2.ActionSupport;


public class LoginAction extends ActionSupport {
    private Integer age = null;
    private String name = null;
    private String email = null;

    public LoginAction() {
    }

    public void setAge(Integer age) {
        this.age = age;
    }

    public Integer getAge() {
        return this.age;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail() {
        return this.email;
    }

    public String execute() throws Exception {
        System.out.println(this.age);
        return !this.name.isEmpty() && !this.email.isEmpty() ? "success" : "error";
    }
}
```

写一个age参数的validation，`LoginAction-validation.xml`

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE validators PUBLIC
        "-//OpenSymphony Group//XWork Validator 1.0//EN"
        "http://www.opensymphony.com/xwork/xwork-validator-1.0.2.dtd">
<validators>
    <field name="age">
        <field-validator type="int">
            <param name="min">1</param>
            <param name="max">150</param>
            <message>test</message>
        </field-validator>
    </field>
</validators>
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
    <s:textfield name="name" label="name" />
    <s:textfield name="email" label="email" />
    <s:textfield name="age" label="age" />
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
    <title>S2-007</title>
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
        <action name="login" class="io.github.milkfr.LoginAction">
            <result name="success">/welcome.jsp</result>
            <result name="error">/index.jsp</result>
            <result name="input">/index.jsp</result>
        </action>
    </package>
</struts>
```

#### 漏洞利用
发出请求，包体内容的age参数为`'+(#application)+'`

![0-1](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/0-1.png)

返回内容为

![0-2](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/0-2.png)

返回的内容是application这个对象在ognl上下文环境中的值，如果我们和s2-001一样，输入`'+(#1+1)+'`，返回值就变成了11，字符串拼接了

### 0x01 漏洞分析
#### 如何定位到intercept
我们的思路肯定和上文一样，现在Action中打断点，判断是HTTP包到Struts2的Request（不一定代码写的是Request，只是比喻）的过程中发生了问题还是生成Response的时候，很明显，debug一下根本没有到Action中就返回了，所以可以判断是在HTTP包转换到Java世界的时候发生了问题

如果看过我之前对struts2结构分析的文章，就应该知道struts2是一个servlet中的Filter，从`org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter`开始，分成了初始化和实际处理HTTP请求两个部分

我们需要从实际处理HTTP请求开始debug，也就是StrutsPrepareAndExecuteFilter的doFilter方法开始，然后一路step over和step in下去，最后来到了`DefaultActionInvocation.invoke`函数下

调用的堆栈信息如下

![1-1](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-1.png)

```
if (this.interceptors.hasNext()) {
    InterceptorMapping interceptor = (InterceptorMapping)this.interceptors.next();
    String interceptorMsg = "interceptor: " + interceptor.getName();
    UtilTimerStack.push(interceptorMsg);

    try {
        this.resultCode = interceptor.getInterceptor().intercept(this);
    } finally {
        UtilTimerStack.pop(interceptorMsg);
    }
} else {
    this.resultCode = this.invokeActionOnly();
}
```

在这个debug过程中会发现到`this.resultCode = interceptor.getInterceptor().intercept(this);`这一行进入了循环，`intercept`方法会中再调用`invoke`，了解struts2结构的话会知道struts2默认有18个intercept，这里肯定是要循环调用的

循环完了结果就结束了，没有走到下面的`invokeActionOnly`，其实这个函数是调用Action的，我们最开始debug没有经过action，说明在intercept循环的时候就触发漏洞了

#### 如何定位到ConversionErrorInterceptor
实际上这个很困难，因为如果把18个intercept全部debug一边，对耐心是一种很大的考验，还不包括万一哪里看漏了要重来一边

比较好的方式是官网公告上面有说明，有提示conversion error，然后就是环境用了validation，了解开发的还可能知道intercept用了那几个和这个有关

> User input is evaluated as an OGNL expression when there's a conversion error. This allows a malicious user to execute arbitrary code. A more detailed description is found in the referenced JIRA ticket.

我感觉没有什么好的方法，是在没有什么信息就只能硬debug，如果你没有看过别人的分析文章，你就和我一样硬debug，你会发现你定位不出来，因为不管这里intercept做什么操作，都会没有问题，它加个引号算问题吗，你怎么知道算问题？

这里直接放弃从intercept进行定位，总表象看最后通过jsp返回，所以我们先到jsp看看有没有什么问题

#### JSP定位
通过jsp的生成过程debug，也就是和s2-001一样的过程，调用栈如下

![1-5](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-5.png)

这里我们将经过validation的age和未经过的name进行比较，同样输入他们的值为`'+(#application)+'`，可以发现`stack.findValue`后它们的值是不一样的

![1-6](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-6.png)

![1-7](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-7.png)

继续跟进`stack.findValue`

![1-8](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-8.png)

到了这里，调用过程中存在一个compile函数，去掉了引号，变成了一个OGNL表达式，这里就能发现为什么多了个引号？

#### 再谈定位ConversionErrorIntercept
我们跟进ConversionErrorInterceptor的intercept方法

![1-2](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-2.png)

![1-3](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-3.png)

![1-4](https://milkfr.github.io/assets/images/posts/2019-03-22-analysis-struts2-ognl-rce-2/1-4.png)

跟进一下可以发现，这里做了几个操作

将age和它的值放入了fakie、ognlstack.root和original.property.override三者中，然后调用过的getOverrideExpr方法中使用了给原来的值拼接了一个单引号

最后value变成了`''+(#application)+''`

此时才算能明白问题的成因，和网上找到这个引号就算分析出了问题我觉得是不行的

#### 漏洞修复
因为这个其实就接近注入漏洞了，所以使用了转义进行修复

### 0x02 反思如何定位漏洞所在
回顾我们上面的过程

* 搭建环境
* 根据数据流转导致漏洞的规则，从action定位问题发生在intercept中
* 无法定位到具体的intercept，只能从jsp在定位，发现传入的值并compile后多了引号
* debug出加引号的intercept，也就是ConversionErrorIntercept
